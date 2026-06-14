#!/usr/bin/env python3
"""
OffSploit - Adım 1 Testleri: Config Doğrulama ve Structured Output
====================================================================
"""

import json
import tempfile
from pathlib import Path

import pytest


# ─────────────────────────────────────────────
# Test 1: Geçerli config ile OffSploitConfig başarıyla oluşur
# ─────────────────────────────────────────────

def test_valid_config_creation():
    """Geçerli bir config dict'i ile OffSploitConfig başarıyla oluşmalı."""
    from offsploit.config_schema import OffSploitConfig

    valid_data = {
        "ollama_url": "http://localhost:11434",
        "ollama_model": "qwen2.5-coder:14b",
        "ollama_timeout": 300,
        "chromadb_path": "./offsploit_chromadb",
        "collection_name": "offsploit_db",
        "exploitdb_root": "exploitdb",
        "csv_path": "exploitdb/files_exploits.csv",
        "top_k": 2,
        "output_dir": "./output",
        "llm_provider": "ollama",
        "api_key": "",
        "embedding_provider": "ollama",
        "embedding_model": "nomic-embed-text",
        "use_docker_sandbox": True,
        "docker_memory_limit": "256m",
        "docker_cpu_limit": 0.5,
        "docker_timeout": 30,
        "use_swarm": True,
        "swarm_max_rounds": 3,
        "opsec_sensitivity": "moderate",
        "evasion_level": "advanced",
        "state_machine_persist": False,
    }

    config = OffSploitConfig.from_dict(valid_data)
    assert config.ollama_url == "http://localhost:11434"
    assert config.ollama_model == "qwen2.5-coder:14b"
    assert config.ollama_timeout == 300
    assert config.top_k == 2
    assert config.llm_provider == "ollama"
    assert config.docker_cpu_limit == 0.5
    assert config.opsec_sensitivity == "moderate"
    assert config.evasion_level == "advanced"


# ─────────────────────────────────────────────
# Test 2: Hatalı tip ile ConfigError fırlatılır
# ─────────────────────────────────────────────

def test_invalid_timeout_type_raises():
    """ollama_timeout alanına string verilirse ConfigError fırlatılmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    bad_data = {
        "ollama_url": "http://localhost:11434",
        "ollama_timeout": "abc",  # Hatalı tip!
    }

    with pytest.raises(ConfigError, match="Config doğrulama hatası"):
        OffSploitConfig.from_dict(bad_data)


def test_invalid_top_k_zero_raises():
    """top_k alanına 0 verilirse ConfigError fırlatılmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    bad_data = {"top_k": 0}

    with pytest.raises(ConfigError):
        OffSploitConfig.from_dict(bad_data)


def test_invalid_top_k_over_limit_raises():
    """top_k alanına 101 verilirse ConfigError fırlatılmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    bad_data = {"top_k": 101}

    with pytest.raises(ConfigError):
        OffSploitConfig.from_dict(bad_data)


# ─────────────────────────────────────────────
# Test 3: Hatalı URL formatı
# ─────────────────────────────────────────────

def test_invalid_ollama_url_raises():
    """ollama_url HTTP/HTTPS ile başlamıyorsa ConfigError fırlatılmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    bad_data = {"ollama_url": "ftp://localhost:11434"}

    with pytest.raises(ConfigError):
        OffSploitConfig.from_dict(bad_data)


# ─────────────────────────────────────────────
# Test 4: Varsayılan değerlerle minimal config
# ─────────────────────────────────────────────

def test_minimal_config_with_defaults():
    """Boş dict ile OffSploitConfig varsayılan değerlerle oluşmalı."""
    from offsploit.config_schema import OffSploitConfig

    config = OffSploitConfig.from_dict({})
    assert config.ollama_url == "http://localhost:11434"
    assert config.ollama_timeout == 300
    assert config.top_k == 2
    assert config.llm_provider == "ollama"


# ─────────────────────────────────────────────
# Test 5: JSON dosyasından okuma
# ─────────────────────────────────────────────

def test_from_json_file():
    """Geçerli config.json dosyasından OffSploitConfig oluşturulmalı."""
    from offsploit.config_schema import OffSploitConfig

    data = {
        "ollama_url": "http://localhost:11434",
        "ollama_model": "test-model",
        "ollama_timeout": 120,
        "top_k": 5,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        config = OffSploitConfig.from_json(f.name)

    assert config.ollama_model == "test-model"
    assert config.ollama_timeout == 120
    assert config.top_k == 5

    # Temizle
    Path(f.name).unlink(missing_ok=True)


def test_from_json_missing_file_raises():
    """Mevcut olmayan dosya ile ConfigError fırlatılmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    with pytest.raises(ConfigError, match="Config dosyası bulunamadı"):
        OffSploitConfig.from_json("/nonexistent/path/config.json")


def test_from_json_invalid_json_raises():
    """Geçersiz JSON dosyası ile ConfigError fırlatılmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write("{ INVALID JSON }")
        f.flush()

        with pytest.raises(ConfigError, match="geçerli JSON değil"):
            OffSploitConfig.from_json(f.name)

    Path(f.name).unlink(missing_ok=True)


# ─────────────────────────────────────────────
# Test 6: to_dict dönüşümü
# ─────────────────────────────────────────────

def test_to_dict_roundtrip():
    """OffSploitConfig -> to_dict -> from_dict roundtrip doğru çalışmalı."""
    from offsploit.config_schema import OffSploitConfig

    original = OffSploitConfig.from_dict({"top_k": 7, "ollama_model": "test"})
    exported = original.to_dict()
    reimported = OffSploitConfig.from_dict(exported)

    assert reimported.top_k == 7
    assert reimported.ollama_model == "test"


# ─────────────────────────────────────────────
# Test 7: opsec_sensitivity/evasion_level doğrulama
# ─────────────────────────────────────────────

def test_invalid_opsec_sensitivity_raises():
    """Geçersiz opsec_sensitivity değeri ConfigError fırlatmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    with pytest.raises(ConfigError):
        OffSploitConfig.from_dict({"opsec_sensitivity": "invalid_value"})


def test_invalid_evasion_level_raises():
    """Geçersiz evasion_level değeri ConfigError fırlatmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    with pytest.raises(ConfigError):
        OffSploitConfig.from_dict({"evasion_level": "super_mega_stealth"})


# ═══════════════════════════════════════════════
# Structured Output Testleri
# ═══════════════════════════════════════════════


# ─────────────────────────────────────────────
# Test 8: Valid JSON structured output parse
# ─────────────────────────────────────────────

def test_structured_output_valid_json():
    """Geçerli JSON çıktısı doğru parse edilmeli."""
    from offsploit.structured_output import LLMExploitOutput, parse_structured_output

    raw = '''```json
{
    "exploit_code": "#include <stdio.h>\\nint main() { return 0; }",
    "target_arch": "x64",
    "required_libs": ["pthread", "socket"]
}
```'''

    result = parse_structured_output(raw, LLMExploitOutput)
    assert result is not None
    assert "#include" in result.exploit_code
    assert result.target_arch == "x64"
    assert "pthread" in result.required_libs
    assert "socket" in result.required_libs


# ─────────────────────────────────────────────
# Test 9: Invalid JSON ile fallback
# ─────────────────────────────────────────────

def test_structured_output_invalid_json_returns_none():
    """Geçersiz JSON çıktısı None döndürmeli (fallback sinyali)."""
    from offsploit.structured_output import LLMExploitOutput, parse_structured_output

    raw = "Bu düz metin bir yanıttır, JSON içermez."
    result = parse_structured_output(raw, LLMExploitOutput)
    assert result is None


# ─────────────────────────────────────────────
# Test 10: parse_exploit_output fallback mekanizması
# ─────────────────────────────────────────────

def test_parse_exploit_output_fallback():
    """JSON parse başarısız olursa code fence parser fallback olarak çalışmalı."""
    from offsploit.structured_output import parse_exploit_output

    raw = '''İşte düzeltilmiş kod:

```python
import socket
s = socket.socket()
s.connect(("192.168.1.1", 4444))
```

Talimatlar: python3 exploit.py ile çalıştırın.'''

    code, arch, libs = parse_exploit_output(raw)
    assert "import socket" in code
    assert "s.connect" in code
    assert arch == "x64"  # varsayılan
    assert libs == []  # boş


# ─────────────────────────────────────────────
# Test 11: parse_exploit_output structured başarı
# ─────────────────────────────────────────────

def test_parse_exploit_output_structured():
    """JSON structured output başarılı olduğunda kod JSON'dan çıkarılmalı."""
    from offsploit.structured_output import parse_exploit_output

    raw = '''```json
{
    "exploit_code": "print('hello')",
    "target_arch": "arm64",
    "required_libs": ["paramiko"]
}
```'''

    code, arch, libs = parse_exploit_output(raw)
    assert code == "print('hello')"
    assert arch == "arm64"
    assert libs == ["paramiko"]


# ─────────────────────────────────────────────
# Test 12: Boş yanıt durumu
# ─────────────────────────────────────────────

def test_parse_exploit_output_empty():
    """Boş LLM yanıtı durumunda boş string döndürmeli."""
    from offsploit.structured_output import parse_exploit_output

    code, arch, libs = parse_exploit_output("")
    assert code == ""
    assert arch == "x64"
    assert libs == []


# ─────────────────────────────────────────────
# Test 13: Bare JSON (fence olmadan)
# ─────────────────────────────────────────────

def test_structured_output_bare_json():
    """Fence olmadan direkt JSON nesnesi parse edilebilmeli."""
    from offsploit.structured_output import LLMExploitOutput, parse_structured_output

    raw = '{"exploit_code": "test_code", "target_arch": "x86", "required_libs": []}'

    result = parse_structured_output(raw, LLMExploitOutput)
    assert result is not None
    assert result.exploit_code == "test_code"
    assert result.target_arch == "x86"


# ─────────────────────────────────────────────
# Test 14: docker_memory_limit format doğrulama
# ─────────────────────────────────────────────

def test_invalid_docker_memory_limit_raises():
    """Geçersiz docker_memory_limit formatı ConfigError fırlatmalı."""
    from offsploit.config_schema import OffSploitConfig
    from offsploit.exceptions import ConfigError

    with pytest.raises(ConfigError):
        OffSploitConfig.from_dict({"docker_memory_limit": "not_valid"})


# ─────────────────────────────────────────────
# Test 15: Ekstra (bilinmeyen) alanlar kabul edilir
# ─────────────────────────────────────────────

def test_extra_fields_accepted():
    """Bilinmeyen alanlar 'extra=allow' ile kabul edilmeli (geriye uyumluluk)."""
    from offsploit.config_schema import OffSploitConfig

    config = OffSploitConfig.from_dict({
        "custom_field": "custom_value",
        "another_unknown": 42,
    })
    exported = config.to_dict()
    assert exported["custom_field"] == "custom_value"
    assert exported["another_unknown"] == 42
