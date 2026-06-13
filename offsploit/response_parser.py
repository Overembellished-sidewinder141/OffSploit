#!/usr/bin/env python3
"""
OffSploit - LLM Yanıt Ayrıştırıcı (Response Parser)
======================================================
Ollama LLM'den gelen yanıtlardaki Markdown code fence'lerini
(```lang ... ```) tespit ederek saf kaynak kodunu çıkarır.

LLM'ler sıklıkla yanıtlarını Markdown formatında döndürür.
Bu modül, adaptasyon ve onarım yanıtlarından temiz kodu ayıklar.
"""

import logging
import re

logger = logging.getLogger("offsploit.parser")

# Markdown code fence pattern:  ```<optional_lang>\n<code>\n```
_CODE_FENCE_PATTERN = re.compile(
    r"```(?:\w+)?\s*\n(.*?)```",
    re.DOTALL,
)

# Satır başındaki markdown açıklama kalıpları
_MARKDOWN_NOISE = re.compile(
    r"^(?:#{1,6}\s+.*|>\s+.*|\*\*.*\*\*\s*$)",
    re.MULTILINE,
)


def extract_code_from_response(response_text: str) -> str:
    """LLM yanıtından saf kaynak kodunu çıkarır.

    Strateji:
        1. Markdown code fence'leri (``` ... ```) varsa en uzun bloğu seç.
        2. Hiç fence yoksa, tüm metni olduğu gibi döndür (fallback).

    Args:
        response_text: LLM'den gelen ham yanıt metni.

    Returns:
        Temizlenmiş kaynak kodu.
    """
    if not response_text or not response_text.strip():
        return ""

    text = response_text.strip()

    # Code fence'leri bul
    matches = _CODE_FENCE_PATTERN.findall(text)

    if matches:
        # En uzun bloğu seç (genellikle asıl kaynak kodu en uzun bloktur)
        best_block = max(matches, key=len).strip()
        logger.info(
            "Code fence tespit edildi: %d blok bulundu, en uzun %d karakter.",
            len(matches),
            len(best_block),
        )
        return best_block

    # Fence yoksa — heuristic (sezgisel) olarak kod olup olmadığını analiz et.
    # Eğer metnin içinde `#include`, `import`, `def `, `void ` gibi kod ibareleri varsa
    # LLM muhtemelen markdown'ı unutmuştur, yine de kodu döndür.
    heuristic_patterns = [
        r"^#include\s+<", r"^import\s+\w+", r"^def\s+\w+\(", r"^class\s+\w+",
        r"int\s+main\s*\(", r"#!/usr/bin/env", r"void\s+\w+\("
    ]

    lines = text.split('\n')
    is_code_likely = any(any(re.search(pat, line.strip()) for pat in heuristic_patterns) for line in lines)

    if is_code_likely:
        logger.warning("Code fence bulunamadı ancak metin içinde kod kalıpları tespit edildi. Metin kod olarak kabul ediliyor.")
        # Satır aralarındaki düz metin olan açıklamaları olabildiğince ayıklamaya çalış
        code_lines = []
        for line in lines:
            # Satır, c/c++/python için geçerli yorum değilse ve hiçbir programlama keyword'u içermiyorsa
            # biraz riskli ama eğer blok halindeyse temizlemeyi deneyebiliriz. Fakat en güvenlisi strip() edip tutmak.
            # Şimdilik markdown noise'ları silmekle yetinelim.
            if not _MARKDOWN_NOISE.match(line):
                code_lines.append(line)
        return "\n".join(code_lines).strip()

    logger.debug("Code fence bulunamadı, tüm yanıt kullanılıyor (%d karakter).", len(text))
    return text


def strip_markdown_artifacts(text: str) -> str:
    """Markdown başlıkları, bold metinler ve blockquote'ları temizler.

    Bu fonksiyon, code fence dışında kalan Markdown kalıntılarını
    (başlıklar, açıklamalar vb.) siler. Genellikle extract_code_from_response
    yeterli olduğundan, bu fonksiyon yalnızca ek temizlik gereken
    durumlarda kullanılır.

    Args:
        text: Temizlenecek metin.

    Returns:
        Markdown kalıntılarından arındırılmış metin.
    """
    if not text:
        return ""

    cleaned = _MARKDOWN_NOISE.sub("", text)

    # Ardışık boş satırları tek satıra düşür
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)

    return cleaned.strip()
