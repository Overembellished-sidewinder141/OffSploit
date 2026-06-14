#!/usr/bin/env python3
"""
OffSploit - Adım 3 Testleri: RAG ve ChromaDB İyileştirmeleri
==============================================================
"""

import tempfile
from pathlib import Path

import pytest


# ─────────────────────────────────────────────
# Test 1: _detect_language fonksiyon testi
# ─────────────────────────────────────────────

def test_detect_language_c():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("exploits/linux/local/1234.c") == "C"


def test_detect_language_python():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("exploits/windows/remote/5678.py") == "Python"


def test_detect_language_ruby():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("exploits/multi/remote/999.rb") == "Ruby"


def test_detect_language_cpp():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("exploits/linux/local/1234.cpp") == "C++"


def test_detect_language_bash():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("exploits/linux/local/1234.sh") == "Bash"


def test_detect_language_unknown():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("exploits/something.xyz") == "Unknown"


def test_detect_language_empty():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._detect_language("") == "Unknown"


# ─────────────────────────────────────────────
# Test 2: _extract_version fonksiyon testi
# ─────────────────────────────────────────────

def test_extract_version_apache():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._extract_version("Apache 2.4.49 - Path Traversal") == "2.4.49"


def test_extract_version_openssh():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._extract_version("OpenSSH 7.2p2 - Username Enumeration") == "7.2"


def test_extract_version_with_suffix():
    from offsploit.chromadb_ingest import Ingestor
    version = Ingestor._extract_version("vsftpd 2.3.4 - Backdoor Command Execution")
    assert version == "2.3.4"


def test_extract_version_range():
    from offsploit.chromadb_ingest import Ingestor
    version = Ingestor._extract_version("WordPress < 5.8.3 - SQL Injection")
    assert version == "5.8.3"


def test_extract_version_none():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._extract_version("Generic Buffer Overflow") == ""


def test_extract_version_empty():
    from offsploit.chromadb_ingest import Ingestor
    assert Ingestor._extract_version("") == ""


# ─────────────────────────────────────────────
# Test 3: OllamaEmbeddingProvider model-aware prefix
# ─────────────────────────────────────────────

def test_mxbai_document_prefix():
    from offsploit.rag_engine import OllamaEmbeddingProvider
    provider = OllamaEmbeddingProvider(model="mxbai-embed-large")
    prefix = provider._get_document_prefix()
    assert "Represent this sentence" in prefix


def test_mxbai_query_prefix():
    from offsploit.rag_engine import OllamaEmbeddingProvider
    provider = OllamaEmbeddingProvider(model="mxbai-embed-large")
    prefix = provider._get_query_prefix()
    assert "Represent this sentence" in prefix


def test_nomic_document_prefix():
    from offsploit.rag_engine import OllamaEmbeddingProvider
    provider = OllamaEmbeddingProvider(model="nomic-embed-text")
    prefix = provider._get_document_prefix()
    assert prefix == "search_document: "


def test_nomic_query_prefix():
    from offsploit.rag_engine import OllamaEmbeddingProvider
    provider = OllamaEmbeddingProvider(model="nomic-embed-text")
    prefix = provider._get_query_prefix()
    assert prefix == "search_query: "


def test_generic_model_no_prefix():
    from offsploit.rag_engine import OllamaEmbeddingProvider
    provider = OllamaEmbeddingProvider(model="custom-embed-v1")
    assert provider._get_document_prefix() == ""
    assert provider._get_query_prefix() == ""


# ─────────────────────────────────────────────
# Test 4: ChromaDB metadata filtreleme (in-memory)
# ─────────────────────────────────────────────

def test_chromadb_metadata_filtering():
    """Geçici ChromaDB'de 2 mock exploit ekle, platform filtresiyle arama yap."""
    import chromadb

    # In-memory client (Windows file lock sorununu önler)
    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        name="test_filter_db",
        metadata={"hnsw:space": "cosine"},
    )

    # Basit mock embeddings (boyut=4)
    collection.add(
        ids=["exploit-linux-1"],
        embeddings=[[0.1, 0.2, 0.3, 0.4]],
        documents=["Linux SSH brute force exploit"],
        metadatas=[{
            "platform": "Linux",
            "language": "Python",
            "service_version": "7.2",
            "file": "exploits/linux/remote/123.py",
            "type": "remote",
        }],
    )
    collection.add(
        ids=["exploit-windows-1"],
        embeddings=[[0.15, 0.25, 0.35, 0.45]],
        documents=["Windows SMB remote code execution"],
        metadatas=[{
            "platform": "Windows",
            "language": "C",
            "service_version": "3.0.1",
            "file": "exploits/windows/remote/456.c",
            "type": "remote",
        }],
    )

    # Filtresiz arama → 2 sonuç
    results_all = collection.query(
        query_embeddings=[[0.1, 0.2, 0.3, 0.4]],
        n_results=10,
    )
    assert len(results_all["ids"][0]) == 2

    # Windows filtreli arama → sadece 1 sonuç
    results_win = collection.query(
        query_embeddings=[[0.1, 0.2, 0.3, 0.4]],
        n_results=10,
        where={"platform": "Windows"},
    )
    assert len(results_win["ids"][0]) == 1
    assert results_win["ids"][0][0] == "exploit-windows-1"
    assert results_win["metadatas"][0][0]["platform"] == "Windows"
    assert results_win["metadatas"][0][0]["language"] == "C"

    # Linux filtreli arama → sadece 1 sonuç
    results_linux = collection.query(
        query_embeddings=[[0.1, 0.2, 0.3, 0.4]],
        n_results=10,
        where={"platform": "Linux"},
    )
    assert len(results_linux["ids"][0]) == 1
    assert results_linux["ids"][0][0] == "exploit-linux-1"
    assert results_linux["metadatas"][0][0]["language"] == "Python"


# ─────────────────────────────────────────────
# Test 5: Dil filtresi ile arama
# ─────────────────────────────────────────────

def test_chromadb_language_filtering():
    """Dil metadatasıyla filtreleme doğru çalışmalı."""
    import chromadb

    client = chromadb.EphemeralClient()
    collection = client.get_or_create_collection(
        name="test_lang_db",
        metadata={"hnsw:space": "cosine"},
    )

    collection.add(
        ids=["py-exploit-1"],
        embeddings=[[0.5, 0.5, 0.5, 0.5]],
        documents=["Python buffer overflow"],
        metadatas=[{"language": "Python", "platform": "Linux"}],
    )
    collection.add(
        ids=["c-exploit-1"],
        embeddings=[[0.6, 0.6, 0.6, 0.6]],
        documents=["C stack overflow"],
        metadatas=[{"language": "C", "platform": "Linux"}],
    )

    # Python filtresi
    results = collection.query(
        query_embeddings=[[0.5, 0.5, 0.5, 0.5]],
        n_results=10,
        where={"language": "Python"},
    )
    assert len(results["ids"][0]) == 1
    assert results["ids"][0][0] == "py-exploit-1"


# ─────────────────────────────────────────────
# Test 6: config.json embedding_model güncellemesi
# ─────────────────────────────────────────────

def test_config_default_embedding_model():
    """Config varsayılan embedding_model mxbai-embed-large olmalı."""
    from offsploit.config_schema import OffSploitConfig

    # Varsayılan config mevcut projeden okunmaz, ama default değeri kontrol edebiliriz
    # Burada config.json dosyasını doğrudan kontrol ediyoruz
    config_path = Path(__file__).parent.parent / "config.json"
    if config_path.exists():
        import json
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data.get("embedding_model") == "mxbai-embed-large", \
            f"config.json embedding_model değeri yanlış: {data.get('embedding_model')}"


# ─────────────────────────────────────────────
# Test 7: search() where parametresi
# ─────────────────────────────────────────────

def test_rag_search_accepts_where_parameter():
    """OffSploitRAG.search() metodu 'where' parametresi kabul etmeli."""
    import inspect
    from offsploit.rag_engine import OffSploitRAG

    sig = inspect.signature(OffSploitRAG.search)
    params = list(sig.parameters.keys())
    assert "where" in params, "search() metodu 'where' parametresi kabul etmiyor!"
