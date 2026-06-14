#!/usr/bin/env python3
"""
OffSploit - Structured Output Parser
======================================
LLM'den dönen yanıtları serbest metin yerine JSON schema ile
parse eden modüller. Pydantic modelleriyle tip-güvenli çıktı sağlar.
"""

import json
import logging
import re
from typing import Any, TypeVar

from pydantic import BaseModel, Field

from offsploit.response_parser import extract_code_from_response

logger = logging.getLogger("offsploit.structured_output")

T = TypeVar("T", bound=BaseModel)


# ─────────────────────────────────────────────
# LLM Output Pydantic Modelleri
# ─────────────────────────────────────────────


class LLMExploitOutput(BaseModel):
    """LLM exploit uyarlama çıktı şeması.

    LLM'den dönen yanıtlar bu formata uymalıdır.
    """

    exploit_code: str = Field(
        ...,
        description="Uyarlanmış exploit kaynak kodu",
    )
    target_arch: str = Field(
        default="x64",
        description="Hedef mimari (x86, x64, arm, arm64)",
    )
    required_libs: list[str] = Field(
        default_factory=list,
        description="Gerekli kütüphane/bağımlılık listesi",
    )


class LLMFixOutput(BaseModel):
    """LLM kod onarım çıktı şeması."""

    fixed_code: str = Field(
        ...,
        description="Düzeltilmiş kaynak kodu",
    )
    changes_made: list[str] = Field(
        default_factory=list,
        description="Yapılan değişikliklerin listesi",
    )


class LLMOpsecOutput(BaseModel):
    """OPSEC Agent analiz çıktı şeması."""

    passed: bool = Field(
        ...,
        description="OPSEC kontrolünden geçti mi",
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Tespit edilen bulgular listesi",
    )
    summary: str = Field(
        default="",
        description="Analiz özeti",
    )


# ─────────────────────────────────────────────
# JSON Extraction Helpers
# ─────────────────────────────────────────────

# JSON code fence pattern: ```json\n{...}\n```
_JSON_FENCE_PATTERN = re.compile(
    r"```(?:json)?\s*\n(\{.*?\})\s*```",
    re.DOTALL,
)

# Bare JSON object pattern (no fence)
_BARE_JSON_PATTERN = re.compile(
    r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})",
    re.DOTALL,
)


def _extract_json_from_text(text: str) -> str | None:
    """Metin içinden JSON nesnesini çıkarır.

    Önce code fence'li JSON arar, yoksa bare JSON arar.
    """
    # 1. Code fence içinde JSON ara
    fence_match = _JSON_FENCE_PATTERN.search(text)
    if fence_match:
        return fence_match.group(1).strip()

    # 2. Bare JSON ara
    bare_match = _BARE_JSON_PATTERN.search(text)
    if bare_match:
        candidate = bare_match.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            pass

    return None


def parse_structured_output(raw: str, schema: type[T]) -> T | None:
    """LLM yanıtını yapılandırılmış Pydantic modeline dönüştürür.

    Strateji:
        1. Metin içinden JSON nesnesini çıkar
        2. JSON'ı Pydantic modeline parse et
        3. Başarısızsa None döndür (caller fallback yapabilir)

    Args:
        raw: LLM'den gelen ham yanıt metni.
        schema: Hedef Pydantic model sınıfı.

    Returns:
        Parse edilmiş Pydantic model nesnesi veya None.
    """
    if not raw or not raw.strip():
        logger.warning("Boş LLM yanıtı alındı.")
        return None

    # JSON çıkar
    json_str = _extract_json_from_text(raw)
    if not json_str:
        logger.debug("LLM yanıtından JSON çıkarılamadı, fallback kullanılacak.")
        return None

    # Pydantic parse
    try:
        parsed = schema.model_validate_json(json_str)
        logger.info("Structured output başarıyla parse edildi: %s", schema.__name__)
        return parsed
    except Exception as e:
        logger.warning(
            "Structured output parse hatası (%s): %s",
            schema.__name__,
            e,
        )
        return None


def parse_exploit_output(raw: str) -> tuple[str, str, list[str]]:
    """LLM exploit çıktısını parse eder.

    Structured output başarılıysa JSON'dan, değilse
    fallback olarak mevcut code fence parser'ından kod çıkarır.

    Args:
        raw: LLM'den gelen ham yanıt.

    Returns:
        Tuple[exploit_code, target_arch, required_libs]
    """
    # Structured output dene
    result = parse_structured_output(raw, LLMExploitOutput)
    if result and result.exploit_code.strip():
        logger.info("Structured exploit output kullanılıyor.")
        return result.exploit_code, result.target_arch, result.required_libs

    # Fallback: Mevcut code fence parser
    logger.info("Fallback: extract_code_from_response kullanılıyor.")
    code = extract_code_from_response(raw)
    return code, "x64", []


def parse_fix_output(raw: str) -> str:
    """LLM fix çıktısını parse eder.

    Structured output başarılıysa JSON'dan, değilse
    fallback olarak mevcut code fence parser'ından kod çıkarır.

    Args:
        raw: LLM'den gelen ham yanıt.

    Returns:
        Düzeltilmiş kaynak kodu.
    """
    result = parse_structured_output(raw, LLMFixOutput)
    if result and result.fixed_code.strip():
        return result.fixed_code

    return extract_code_from_response(raw)


def get_exploit_json_schema_prompt() -> str:
    """LLM'ye JSON çıktı formatını açıklayan prompt parçası döndürür."""
    return (
        "\n\nÖNEMLİ: Yanıtını MUTLAKA aşağıdaki JSON formatında ver:\n"
        '```json\n'
        '{\n'
        '  "exploit_code": "... (tam uyarlanmış kaynak kodu) ...",\n'
        '  "target_arch": "x64",\n'
        '  "required_libs": ["lib1", "lib2"]\n'
        '}\n'
        '```\n'
        "JSON dışında hiçbir metin ekleme."
    )
