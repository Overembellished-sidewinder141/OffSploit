#!/usr/bin/env python3
"""
OffSploit - RAG Retrieval Motoru v1.0
======================================
ChromaDB'den semantik benzerlik araması yaparak en uygun exploit'leri
bulur. Çoklu embedding provider desteği (Ollama nomic-embed-text,
SentenceTransformers) ve multi-collection arama yeteneği ile donatılmıştır.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chromadb
import requests

from offsploit.exceptions import RAGSearchError

logger = logging.getLogger("offsploit.rag")


# ─────────────────────────────────────────────
# Embedding Provider Abstraction
# ─────────────────────────────────────────────

class EmbeddingProvider(ABC):
    """Embedding model'leri için soyut temel sınıf."""

    @abstractmethod
    def encode(self, texts: list[str]) -> list[list[float]]:
        """Metinleri embedding vektörlerine dönüştürür."""
        ...

    @abstractmethod
    def encode_query(self, query: str) -> list[float]:
        """Tek bir sorgu metnini embedding vektörüne dönüştürür."""
        ...

    @abstractmethod
    def get_dimension(self) -> int:
        """Embedding boyutunu döndürür."""
        ...


class OllamaEmbeddingProvider(EmbeddingProvider):
    """Ollama API üzerinden embedding üretir (nomic-embed-text, jina vb.)."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mxbai-embed-large", timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._dimension: int | None = None
        logger.info("OllamaEmbeddingProvider başlatıldı: model=%s, url=%s", model, base_url)

    def _call_api(self, texts: list[str]) -> list[list[float]]:
        """Ollama /api/embed endpoint'ine toplu istek gönderir."""
        url = f"{self.base_url}/api/embed"
        payload = {
            "model": self.model,
            "input": texts
        }
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            embeddings = data.get("embeddings", [])
            if embeddings and self._dimension is None:
                self._dimension = len(embeddings[0])
            return embeddings
        except requests.exceptions.ConnectionError as e:
            logger.error("Ollama embedding API'ye bağlanılamadı: %s", e)
            raise RAGSearchError(f"Ollama embedding API bağlantı hatası: {e}") from e
        except Exception as e:
            logger.error("Ollama embedding hatası: %s", e)
            raise RAGSearchError(f"Ollama embedding hatası: {e}") from e

    def _get_document_prefix(self) -> str:
        """Model adına göre döküman embedding prefix'i döndürür."""
        model_lower = self.model.lower()
        if "nomic" in model_lower:
            return "search_document: "
        elif "mxbai" in model_lower:
            return "Represent this sentence for searching relevant passages: "
        return ""

    def _get_query_prefix(self) -> str:
        """Model adına göre sorgu embedding prefix'i döndürür."""
        model_lower = self.model.lower()
        if "nomic" in model_lower:
            return "search_query: "
        elif "mxbai" in model_lower:
            return "Represent this sentence for searching relevant passages: "
        return ""

    def encode(self, texts: list[str]) -> list[list[float]]:
        """Döküman metinlerini embedding'e çevirir. Model'e göre uygun prefix eklenir."""
        prefix = self._get_document_prefix()
        prefixed = [f"{prefix}{t}" for t in texts]
        # Batch halinde işle (Ollama API batch destekler)
        batch_size = 64
        all_embeddings: list[list[float]] = []
        for i in range(0, len(prefixed), batch_size):
            batch = prefixed[i:i + batch_size]
            embeddings = self._call_api(batch)
            all_embeddings.extend(embeddings)
        return all_embeddings

    def encode_query(self, query: str) -> list[float]:
        """Sorgu metnini embedding'e çevirir. Model'e göre uygun prefix eklenir."""
        prefix = self._get_query_prefix()
        prefixed = f"{prefix}{query}"
        embeddings = self._call_api([prefixed])
        if embeddings:
            return embeddings[0]
        raise RAGSearchError("Ollama embedding boş yanıt döndürdü.")

    def get_dimension(self) -> int:
        if self._dimension is None:
            # Test çağrısı ile boyutu öğren
            test_emb = self._call_api(["test"])
            if test_emb:
                self._dimension = len(test_emb[0])
        return self._dimension or 768


class SentenceTransformerProvider(EmbeddingProvider):
    """sentence-transformers kütüphanesi üzerinden embedding üretir (geriye uyumluluk)."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        logger.info("SentenceTransformerProvider başlatıldı: model=%s", model_name)

    def _load_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            logger.info("SentenceTransformer yükleniyor: %s", self.model_name)
            try:
                self._model = SentenceTransformer(self.model_name)
            except Exception as exc:
                raise RAGSearchError(f"Embedding modeli yüklenemedi: {exc}") from exc
        return self._model

    def encode(self, texts: list[str]) -> list[list[float]]:
        model = self._load_model()
        return model.encode(texts, show_progress_bar=False, batch_size=128).tolist()

    def encode_query(self, query: str) -> list[float]:
        model = self._load_model()
        return model.encode(query).tolist()

    def get_dimension(self) -> int:
        model = self._load_model()
        return model.get_sentence_embedding_dimension()


def create_embedding_provider(config: dict) -> EmbeddingProvider:
    """Config'e göre uygun embedding provider'ı oluşturur (Factory)."""
    provider_type = config.get("embedding_provider", "sentence_transformer").lower()
    model_name = config.get("embedding_model", "all-MiniLM-L6-v2")

    if provider_type == "ollama":
        return OllamaEmbeddingProvider(
            base_url=config.get("ollama_url", "http://localhost:11434"),
            model=model_name,
            timeout=int(config.get("ollama_timeout", 120))
        )
    else:
        return SentenceTransformerProvider(model_name=model_name)


# ─────────────────────────────────────────────
# Exploit Match Dataclass
# ─────────────────────────────────────────────

@dataclass
class ExploitMatch:
    """ChromaDB sorgusundan dönen tekil bir exploit eşleşmesi.

    Attributes:
        exploit_id: ChromaDB'deki belge kimliği.
        description: Exploit açıklaması (document).
        file_path:  Exploit-DB içindeki dosya yolu (metadata).
        platform:   Hedef platform (metadata).
        exploit_type: Exploit türü (metadata).
        distance:   Kosinüs mesafesi (düşük = daha yakın eşleşme).
        source_code: Diskten okunan ham exploit kaynak kodu.
    """

    exploit_id: str
    description: str
    file_path: str
    platform: str
    exploit_type: str
    distance: float
    source_code: str = ""


# ─────────────────────────────────────────────
# RAG Engine
# ─────────────────────────────────────────────

class OffSploitRAG:
    """ChromaDB üzerinden semantik exploit araması yapan RAG motoru v1.

    Multi-collection arama, çoklu embedding provider ve
    BloodHound AD verisi entegrasyonu destekler.
    """

    DEFAULT_EXPLOIT_COLLECTION = "offsploit_db"
    DEFAULT_AD_COLLECTION = "offsploit_ad"

    def __init__(
        self,
        db_path: str = "./offsploit_chromadb",
        collection_name: str = "offsploit_db",
        model_name: str = "all-MiniLM-L6-v2",
        exploitdb_root: str = "exploitdb",
        top_k: int = 2,
        config: dict | None = None,
    ) -> None:
        self.db_path: str = db_path
        self.collection_name: str = collection_name
        self.model_name: str = model_name
        self.exploitdb_root: Path = Path(exploitdb_root)
        self.top_k: int = top_k

        # Embedding provider: config varsa factory kullan, yoksa eski uyumlu SentenceTransformer
        if config:
            self._provider: EmbeddingProvider = create_embedding_provider(config)
        else:
            self._provider = SentenceTransformerProvider(model_name=model_name)

        self._collections: dict[str, chromadb.Collection] = {}

    # ── ChromaDB Collection Yönetimi ──

    def _get_collection(self, name: str | None = None) -> chromadb.Collection:
        """ChromaDB koleksiyonunu açar (lazy + cache)."""
        col_name = name or self.collection_name
        if col_name not in self._collections:
            logger.info("ChromaDB koleksiyonu açılıyor: %s (path=%s)", col_name, self.db_path)
            try:
                client = chromadb.PersistentClient(path=self.db_path)
                self._collections[col_name] = client.get_collection(name=col_name)
                count = self._collections[col_name].count()
                logger.info("Koleksiyon '%s' açıldı — %d kayıt mevcut.", col_name, count)
            except Exception as exc:
                logger.critical("ChromaDB koleksiyonu açılamadı (%s): %s", col_name, exc, exc_info=True)
                raise RAGSearchError(f"ChromaDB koleksiyonu açılamadı ({col_name}): {exc}") from exc
        return self._collections[col_name]

    # ── Exploit Kaynak Kodu Okuma ──

    def _read_exploit_source(self, relative_path: str) -> str:
        """Yerel Exploit-DB klonundan exploit kaynak kodunu okur."""
        full_path: Path = self.exploitdb_root / relative_path

        if not full_path.exists():
            logger.warning("Exploit dosyası bulunamadı: %s", full_path)
            return ""

        try:
            source: str = full_path.read_text(encoding="utf-8", errors="replace")
            logger.info("Exploit kaynak kodu okundu: %s (%d karakter)", full_path.name, len(source))
            return source
        except Exception as exc:
            logger.error("Exploit dosyası okunamadı (%s): %s", full_path, exc, exc_info=True)
            return ""

    # ── Arama API'leri ──

    def search(self, query: str, top_k: int | None = None, collection_name: str | None = None, where: dict | None = None) -> list[ExploitMatch]:
        """Tek bir servis sorgusu için ChromaDB'de semantik arama yapar.

        Args:
            query:  Aranacak metin (örn. "vsftpd 2.3.4").
            top_k:  Döndürülecek sonuç sayısı (varsayılan: self.top_k).
            collection_name: Aranacak koleksiyon adı (varsayılan: self.collection_name).
            where: ChromaDB metadata filtresi (opsiyonel).
                   Örn: {"platform": "Windows"} veya {"language": "Python"}

        Returns:
            ExploitMatch nesnelerinin listesi (mesafeye göre sıralı).
        """
        k: int = top_k if top_k is not None else self.top_k
        collection = self._get_collection(collection_name)

        logger.info('Sorgulanıyor: "%s" (top_k=%d, collection=%s, where=%s)', query, k, collection_name or self.collection_name, where)

        try:
            query_embedding = self._provider.encode_query(query)
            query_params: dict[str, Any] = {
                "query_embeddings": [query_embedding],
                "n_results": k,
            }
            if where:
                query_params["where"] = where
            results: dict[str, Any] = collection.query(**query_params)
        except Exception as exc:
            logger.error("ChromaDB sorgu hatası: %s", exc, exc_info=True)
            return []

        matches: list[ExploitMatch] = []

        ids: list[str] = results.get("ids", [[]])[0]
        documents: list[str] = results.get("documents", [[]])[0]
        metadatas: list[dict[str, str]] = results.get("metadatas", [[]])[0]
        distances: list[float] = results.get("distances", [[]])[0]

        for i, doc_id in enumerate(ids):
            meta: dict[str, str] = metadatas[i] if i < len(metadatas) else {}
            file_path: str = meta.get("file", "")
            distance: float = distances[i] if i < len(distances) else 999.0

            source_code: str = self._read_exploit_source(file_path) if file_path else ""

            match = ExploitMatch(
                exploit_id=doc_id,
                description=documents[i] if i < len(documents) else "",
                file_path=file_path,
                platform=meta.get("platform", ""),
                exploit_type=meta.get("type", ""),
                distance=distance,
                source_code=source_code,
            )
            matches.append(match)

            logger.info(
                "  [%d] %s (mesafe=%.4f) — %s",
                i + 1,
                match.description[:80],
                match.distance,
                match.file_path,
            )

        return matches

    def search_multiple(
        self, queries: list[str], top_k: int | None = None
    ) -> dict[str, list[ExploitMatch]]:
        """Birden fazla servis sorgusu için toplu arama yapar."""
        results: dict[str, list[ExploitMatch]] = {}

        for query in queries:
            logger.info("─" * 50)
            matches: list[ExploitMatch] = self.search(query, top_k=top_k)
            results[query] = matches

        total_found: int = sum(len(m) for m in results.values())
        logger.info(
            "Toplu arama tamamlandı: %d sorgu → %d eşleşme.",
            len(queries),
            total_found,
        )
        return results

    def search_ad(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Active Directory koleksiyonunda semantik arama yapar.

        Args:
            query: AD ile ilgili arama sorgusu (örn. "Domain Admin yetki yolu").
            top_k: Döndürülecek sonuç sayısı.

        Returns:
            AD dökümanlarının listesi.
        """
        try:
            collection = self._get_collection(self.DEFAULT_AD_COLLECTION)
        except RAGSearchError:
            logger.warning("AD koleksiyonu bulunamadı, AD araması atlanıyor.")
            return []

        try:
            query_embedding = self._provider.encode_query(query)
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
            )
        except Exception as exc:
            logger.error("AD ChromaDB sorgu hatası: %s", exc, exc_info=True)
            return []

        ad_results = []
        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for i, doc_id in enumerate(ids):
            ad_results.append({
                "id": doc_id,
                "document": documents[i] if i < len(documents) else "",
                "metadata": metadatas[i] if i < len(metadatas) else {},
                "distance": distances[i] if i < len(distances) else 999.0,
            })

        return ad_results
