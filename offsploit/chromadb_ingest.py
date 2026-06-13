#!/usr/bin/env python3
"""
OffSploit - ChromaDB Veritabanı Hazırlayıcı v1.0 (Ingestor)
==============================================================
Exploit-DB CSV + BloodHound JSON verilerini çoklu embedding provider
desteğiyle ChromaDB'ye aktarır. Kod bazlı context retention için
exploit kaynak kodunun ilk bölümünü composite text'e dahil eder.
"""

import contextlib
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path

import chromadb
import pandas as pd

from offsploit.rag_engine import EmbeddingProvider, SentenceTransformerProvider, create_embedding_provider

logger = logging.getLogger("offsploit.ingest")


class Ingestor:
    """Exploit-DB CSV verisini ChromaDB vektör veritabanına aktaran sınıf v1.

    Yenilikler:
        - Çoklu embedding provider desteği (Ollama, SentenceTransformer)
        - Composite text'e exploit kaynak kodunun ilk 512 karakteri dahil
        - BloodHound AD verisi ingest desteği
    """

    REQUIRED_COLUMNS: list[str] = ["id", "file", "description", "platform", "type"]

    def __init__(
        self,
        csv_path: str = "exploitdb/files_exploits.csv",
        db_path: str = "./offsploit_chromadb",
        collection_name: str = "offsploit_db",
        model_name: str = "all-MiniLM-L6-v2",
        chunk_size: int = 5000,
        progress_callback: Callable[[int, int, str], None] | None = None,
        config: dict | None = None,
        exploitdb_root: str = "exploitdb",
    ) -> None:
        self.csv_path: Path = Path(csv_path)
        self.db_path: str = db_path
        self.collection_name: str = collection_name
        self.model_name: str = model_name
        self.chunk_size: int = chunk_size
        self.progress_callback: Callable[[int, int, str], None] | None = progress_callback
        self.exploitdb_root: Path = Path(exploitdb_root)

        # Embedding provider: config varsa factory, yoksa eski uyumlu SentenceTransformer
        if config:
            self._provider: EmbeddingProvider = create_embedding_provider(config)
        else:
            self._provider = SentenceTransformerProvider(model_name=model_name)

        self._client: chromadb.PersistentClient | None = None
        self._collection: chromadb.Collection | None = None

    # ── ChromaDB Yönetimi ──

    def _init_chromadb(self, col_name: str | None = None) -> chromadb.Collection:
        """ChromaDB istemcisini ve koleksiyonunu başlatır."""
        target_name = col_name or self.collection_name
        logger.info("ChromaDB başlatılıyor → %s (koleksiyon: %s)", self.db_path, target_name)
        try:
            if self._client is None:
                self._client = chromadb.PersistentClient(path=self.db_path)

            existing_collections = [c.name for c in self._client.list_collections()]
            if target_name in existing_collections:
                logger.warning("Mevcut koleksiyon siliniyor: %s", target_name)
                self._client.delete_collection(target_name)

            collection = self._client.get_or_create_collection(
                name=target_name,
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("Koleksiyon hazır: %s", target_name)
            return collection
        except Exception as exc:
            logger.critical("ChromaDB başlatılamadı: %s", exc, exc_info=True)
            raise

    # ── Exploit Kaynak Kodu Snippet ──

    def _read_source_snippet(self, relative_path: str, max_chars: int = 512) -> str:
        """Exploit kaynak kodunun ilk max_chars karakterini okur (context retention)."""
        if not relative_path:
            return ""
        full_path = self.exploitdb_root / relative_path
        if not full_path.exists():
            return ""
        try:
            text = full_path.read_text(encoding="utf-8", errors="replace")
            return text[:max_chars].strip()
        except Exception:
            return ""

    # ── CSV İşlemleri ──

    def read_csv(self) -> pd.DataFrame:
        """CSV dosyasını okur, gerekli sütunları filtreler ve temizler."""
        if not self.csv_path.exists():
            logger.critical("CSV dosyası bulunamadı: %s", self.csv_path)
            raise FileNotFoundError(f"CSV dosyası bulunamadı: {self.csv_path}")

        logger.info("CSV okunuyor: %s", self.csv_path)
        try:
            df: pd.DataFrame = pd.read_csv(self.csv_path, encoding="utf-8")
        except Exception as exc:
            logger.critical("CSV okunamadı: %s", exc, exc_info=True)
            raise

        missing = set(self.REQUIRED_COLUMNS) - set(df.columns)
        if missing:
            logger.critical("Eksik sütunlar: %s", missing)
            raise KeyError(f"CSV'de eksik sütunlar var: {missing}")

        df = df[self.REQUIRED_COLUMNS].copy()

        before_count: int = len(df)
        df.dropna(subset=["description"], inplace=True)
        df["description"] = df["description"].astype(str).str.strip()
        df = df[df["description"].str.len() > 0]
        df.drop_duplicates(subset=["id"], keep="first", inplace=True)
        after_count: int = len(df)

        logger.info(
            "CSV yüklendi: %d kayıt (%d boş description atıldı)",
            after_count,
            before_count - after_count,
        )
        return df

    # ── Ana Ingest Pipeline ──

    def ingest(self) -> int:
        """Tam exploit ingest pipeline'ını çalıştırır."""
        df: pd.DataFrame = self.read_csv()
        collection: chromadb.Collection = self._init_chromadb()

        total_rows: int = len(df)
        ingested: int = 0

        logger.info("Ingest başlıyor: %d kayıt, chunk_size=%d", total_rows, self.chunk_size)

        for start in range(0, total_rows, self.chunk_size):
            end: int = min(start + self.chunk_size, total_rows)
            chunk: pd.DataFrame = df.iloc[start:end]

            descriptions: list[str] = chunk["description"].tolist()

            # Geliştirilmiş composite text: Platform + Type + Description + Code Snippet
            composite_texts: list[str] = []
            for _, row in chunk.iterrows():
                file_path = str(row.get("file", ""))
                code_snippet = self._read_source_snippet(file_path)
                parts = [
                    f"Platform: {row.get('platform', '')}",
                    f"Type: {row.get('type', '')}",
                    f"Description: {row.get('description', '')}",
                ]
                if code_snippet:
                    parts.append(f"Code: {code_snippet}")
                composite_texts.append(" | ".join(parts))

            ids: list[str] = [f"exploit-{row['id']}" for _, row in chunk.iterrows()]

            metadatas: list[dict[str, str]] = [
                {
                    "file": str(row.get("file", "")),
                    "platform": str(row.get("platform", "")),
                    "type": str(row.get("type", "")),
                    "exploit_id": str(row.get("id", "")),
                }
                for _, row in chunk.iterrows()
            ]

            try:
                logger.info("Embedding oluşturuluyor: chunk [%d-%d]", start, end - 1)
                embeddings = self._provider.encode(composite_texts)
            except Exception as exc:
                logger.error(
                    "Embedding hatası (chunk %d-%d): %s", start, end - 1, exc,
                    exc_info=True,
                )
                continue

            try:
                collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    documents=descriptions,
                    metadatas=metadatas,
                )
                ingested += len(ids)
                logger.info(
                    "ChromaDB'ye eklendi: %d/%d (toplam: %d)",
                    len(ids),
                    total_rows,
                    ingested,
                )

                if self.progress_callback:
                    with contextlib.suppress(Exception):
                        self.progress_callback(
                            ingested, total_rows,
                            f"Chunk [{start}-{end - 1}] islendi"
                        )
            except Exception as exc:
                logger.error(
                    "ChromaDB yazma hatası (chunk %d-%d): %s",
                    start, end - 1, exc,
                    exc_info=True,
                )
                continue

        logger.info(
            "Ingest tamamlandı: %d / %d kayıt başarıyla eklendi.",
            ingested,
            total_rows,
        )
        return ingested

    # ── BloodHound AD Verisi Ingest ──

    def ingest_bloodhound(self, folder_path: str, collection_name: str = "offsploit_ad") -> int:
        """BloodHound JSON verilerini ayrı bir ChromaDB koleksiyonuna aktarır.

        Args:
            folder_path: BloodHound JSON dosyalarının bulunduğu dizin.
            collection_name: AD verisi için ChromaDB koleksiyon adı.

        Returns:
            İşlenen AD döküman sayısı.
        """
        folder = Path(folder_path)
        if not folder.is_dir():
            logger.error("BloodHound dizini bulunamadı: %s", folder)
            return 0

        json_files = list(folder.glob("*.json"))
        if not json_files:
            logger.error("BloodHound dizininde JSON dosyası bulunamadı.")
            return 0

        collection = self._init_chromadb(col_name=collection_name)
        ingested = 0

        for json_file in json_files:
            try:
                with open(json_file, encoding="utf-8") as f:
                    data = json.load(f)

                items = data.get("data", [])
                if not items:
                    continue

                documents: list[str] = []
                ids: list[str] = []
                metadatas: list[dict[str, str]] = []

                for idx, item in enumerate(items):
                    props = item.get("Properties", {})
                    node_name = props.get("name", "").upper()
                    node_type = item.get("ObjectIdentifier", "UNKNOWN")

                    if not node_name:
                        node_name = node_type

                    # Relation'ları topla
                    relations = []
                    for ace in item.get("Aces", []):
                        right = ace.get("RightName", "")
                        principal = ace.get("PrincipalSID", ace.get("PrincipalName", ""))
                        if right and principal:
                            relations.append(f"{principal} --{right}--> {node_name}")

                    for member in item.get("Members", []):
                        member_name = member.get("ObjectIdentifier", member.get("MemberName", ""))
                        if member_name:
                            relations.append(f"{member_name} --MemberOf--> {node_name}")

                    # Composite döküman oluştur
                    doc = (
                        f"AD Object: {node_name} | "
                        f"Type: {props.get('objectclass', 'Unknown')} | "
                        f"Domain: {props.get('domain', 'Unknown')} | "
                        f"Enabled: {props.get('enabled', 'Unknown')} | "
                        f"Relations: {'; '.join(relations[:20]) if relations else 'None'}"
                    )

                    documents.append(doc)
                    ids.append(f"ad-{json_file.stem}-{idx}")
                    metadatas.append({
                        "source_file": json_file.name,
                        "node_name": node_name,
                        "node_type": str(props.get("objectclass", "Unknown")),
                        "domain": str(props.get("domain", "")),
                    })

                if documents:
                    try:
                        embeddings = self._provider.encode(documents)
                        collection.add(
                            ids=ids,
                            embeddings=embeddings,
                            documents=documents,
                            metadatas=metadatas,
                        )
                        ingested += len(documents)
                        logger.info("BloodHound dosyası aktarıldı: %s (%d döküman)", json_file.name, len(documents))
                    except Exception as exc:
                        logger.error("BloodHound embedding/ingest hatası (%s): %s", json_file.name, exc)

            except Exception as exc:
                logger.error("BloodHound JSON parse hatası (%s): %s", json_file.name, exc)

        logger.info("BloodHound ingest tamamlandı: %d AD dökümanı aktarıldı.", ingested)
        return ingested


# Doğrudan çalıştırma desteği

def main() -> None:
    """CLI'den doğrudan çağrıldığında çalışır."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(name)-24s │ %(levelname)-8s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    csv_path: str = sys.argv[1] if len(sys.argv) > 1 else "exploitdb/files_exploits.csv"

    ingestor = Ingestor(csv_path=csv_path)
    count: int = ingestor.ingest()
    print(f"\n[✓] Toplam {count} exploit ChromaDB'ye aktarıldı.")


if __name__ == "__main__":
    main()
