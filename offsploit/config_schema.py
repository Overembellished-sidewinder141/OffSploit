#!/usr/bin/env python3
"""
OffSploit - Config Schema (Pydantic v2)
========================================
config.json dosyasını Pydantic modeli ile doğrulayan şema.
Hatalı tip veya eksik parametre girilirse pipeline başlamadan
anlaşılır bir ConfigError fırlatır.
"""

import json
import logging
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from offsploit.exceptions import ConfigError

logger = logging.getLogger("offsploit.config")


class OffSploitConfig(BaseModel):
    """OffSploit yapılandırma şeması.

    Tüm config.json alanlarını tip doğrulama ve varsayılan
    değerlerle modelleyen Pydantic BaseModel.
    """

    # ── LLM Provider ──
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API sunucu URL'si",
    )
    ollama_model: str = Field(
        default="qwen2.5-coder:14b",
        description="Kullanılacak LLM modeli",
    )
    ollama_timeout: int = Field(
        default=300,
        gt=0,
        description="LLM API istek zaman aşımı (saniye)",
    )
    llm_provider: Literal["ollama", "gemini", "openai"] = Field(
        default="ollama",
        description="LLM sağlayıcı türü",
    )
    api_key: str = Field(
        default="",
        description="Cloud LLM API anahtarı (Gemini/OpenAI)",
    )

    # ── Embedding ──
    embedding_provider: Literal["ollama", "sentence_transformer"] = Field(
        default="ollama",
        description="Embedding sağlayıcı türü",
    )
    embedding_model: str = Field(
        default="nomic-embed-text",
        description="Embedding modeli adı",
    )

    # ── ChromaDB & Exploit-DB ──
    chromadb_path: str = Field(
        default="./offsploit_chromadb",
        description="ChromaDB veritabanı yolu",
    )
    collection_name: str = Field(
        default="offsploit_db",
        description="ChromaDB koleksiyon adı",
    )
    exploitdb_root: str = Field(
        default="exploitdb",
        description="Exploit-DB klon dizini",
    )
    csv_path: str = Field(
        default="exploitdb/files_exploits.csv",
        description="Exploit-DB CSV dosya yolu",
    )
    top_k: int = Field(
        default=2,
        gt=0,
        le=100,
        description="RAG aramasında döndürülecek sonuç sayısı",
    )
    output_dir: str = Field(
        default="./output",
        description="Çıktı dizini",
    )

    # ── Docker Sandbox ──
    use_docker_sandbox: bool = Field(
        default=True,
        description="Docker sandbox kullanılsın mı",
    )
    docker_memory_limit: str = Field(
        default="256m",
        description="Docker container bellek limiti",
    )
    docker_cpu_limit: float = Field(
        default=0.5,
        gt=0,
        description="Docker container CPU limiti (çekirdek sayısı)",
    )
    docker_timeout: int = Field(
        default=30,
        gt=0,
        description="Docker container zaman aşımı (saniye)",
    )

    # ── Swarm ──
    use_swarm: bool = Field(
        default=True,
        description="Multi-Agent Swarm kullanılsın mı",
    )
    swarm_max_rounds: int = Field(
        default=3,
        gt=0,
        le=20,
        description="Swarm maksimum tur sayısı",
    )
    opsec_sensitivity: str = Field(
        default="moderate",
        description="OPSEC hassasiyet seviyesi",
    )

    # ── Evasion ──
    evasion_level: str = Field(
        default="advanced",
        description="Evasion seviyesi",
    )

    # ── State Machine ──
    state_machine_persist: bool = Field(
        default=False,
        description="State machine durumunu diske kaydet",
    )

    # ── Opsiyonel / Ekstra ──
    skip_preflight: bool = Field(
        default=False,
        description="Pre-flight kontrolünü atla",
    )

    model_config = {
        "extra": "allow",  # Bilinmeyen alanları kabul et (geriye uyumluluk)
    }

    # ── Validators ──

    @field_validator("ollama_url")
    @classmethod
    def validate_ollama_url(cls, v: str) -> str:
        """URL formatını temel düzeyde doğrular."""
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"ollama_url geçerli bir HTTP/HTTPS URL olmalıdır, aldığımız: '{v}'"
            )
        return v.rstrip("/")

    @field_validator("docker_memory_limit")
    @classmethod
    def validate_docker_memory_limit(cls, v: str) -> str:
        """Docker bellek limiti formatını doğrular (örn. '256m', '1g')."""
        import re
        if not re.match(r"^\d+[bkmgBKMG]?$", v):
            raise ValueError(
                f"docker_memory_limit geçerli bir format olmalıdır (örn. '256m', '1g'), aldığımız: '{v}'"
            )
        return v

    @field_validator("opsec_sensitivity")
    @classmethod
    def validate_opsec_sensitivity(cls, v: str) -> str:
        """OPSEC hassasiyet seviyesini doğrular."""
        allowed = {"low", "moderate", "high", "paranoid"}
        if v.lower() not in allowed:
            raise ValueError(
                f"opsec_sensitivity şu değerlerden biri olmalıdır: {allowed}, aldığımız: '{v}'"
            )
        return v.lower()

    @field_validator("evasion_level")
    @classmethod
    def validate_evasion_level(cls, v: str) -> str:
        """Evasion seviyesini doğrular."""
        allowed = {"none", "basic", "advanced", "paranoid"}
        if v.lower() not in allowed:
            raise ValueError(
                f"evasion_level şu değerlerden biri olmalıdır: {allowed}, aldığımız: '{v}'"
            )
        return v.lower()

    # ── Factory Methods ──

    @classmethod
    def from_json(cls, path: str | Path) -> "OffSploitConfig":
        """JSON dosyasından config nesnesi oluşturur.

        Args:
            path: config.json dosya yolu.

        Returns:
            Doğrulanmış OffSploitConfig nesnesi.

        Raises:
            ConfigError: Dosya okunamadı veya doğrulama başarısız.
        """
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(
                f"Config dosyası bulunamadı: {config_path}",
                detail="config.json dosyasının proje kök dizininde bulunduğundan emin olun.",
            )

        try:
            raw_text = config_path.read_text(encoding="utf-8")
            raw_data = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise ConfigError(
                f"Config dosyası geçerli JSON değil: {e}",
                detail=f"Dosya: {config_path}",
            ) from e
        except Exception as e:
            raise ConfigError(
                f"Config dosyası okunamadı: {e}",
                detail=f"Dosya: {config_path}",
            ) from e

        return cls.from_dict(raw_data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OffSploitConfig":
        """Dict'ten config nesnesi oluşturur.

        Args:
            data: Yapılandırma verileri.

        Returns:
            Doğrulanmış OffSploitConfig nesnesi.

        Raises:
            ConfigError: Doğrulama başarısız.
        """
        try:
            config = cls(**data)
            logger.info("Config doğrulaması başarılı.")
            return config
        except Exception as e:
            raise ConfigError(
                f"Config doğrulama hatası: {e}",
                detail="Lütfen config.json içindeki alan tiplerini ve değerleri kontrol edin.",
            ) from e

    def to_dict(self) -> dict[str, Any]:
        """Config nesnesini dict'e çevirir."""
        return self.model_dump()
