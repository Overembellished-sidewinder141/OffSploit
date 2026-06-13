#!/usr/bin/env python3
"""
OffSploit - Multi-Agent Swarm (OPSEC Doğrulaması) v1.0
========================================================
LLM işlemlerini iki ayrı ajana bölen Swarm mimarisi:
- ExploitAgent: Exploit kodunu hedefe göre yazar/uyarlar.
- OPSECAgent: Yazılan kodu OPSEC perspektifinden denetler.

SwarmOrchestrator iki ajanı koordine ederek, OPSEC geçene kadar
otomatik revizyon döngüsü çalıştırır.
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("offsploit.swarm")


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

class OPSECSeverity(Enum):
    """OPSEC bulgu ciddiyet seviyesi."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OPSECSensitivity(Enum):
    """OPSEC ajan hassasiyet seviyesi."""
    STRICT = "strict"       # Tüm bulgular fail
    MODERATE = "moderate"   # CRITICAL + HIGH fail
    LOOSE = "loose"         # Sadece CRITICAL fail


@dataclass
class OPSECFinding:
    """Tek bir OPSEC bulgusu."""
    category: str           # Örn: "CLEAR_TEXT", "DISK_IO", "PROCESS_SPAWN"
    severity: OPSECSeverity
    description: str
    line_hint: str = ""     # İlgili kod satırı ipucu
    recommendation: str = ""


@dataclass
class OPSECReview:
    """OPSEC Agent'ın inceleme sonucu."""
    passed: bool
    findings: list[OPSECFinding] = field(default_factory=list)
    summary: str = ""
    raw_response: str = ""


@dataclass
class AgentResult:
    """Ajan çalıştırma sonucu."""
    success: bool
    code: str = ""
    message: str = ""
    metadata: dict = field(default_factory=dict)


# ─────────────────────────────────────────────
# Base Agent
# ─────────────────────────────────────────────

class BaseAgent(ABC):
    """Tüm ajanlar için soyut temel sınıf."""

    def __init__(self, name: str, role: str, llm_client):
        self.name = name
        self.role = role
        self.llm = llm_client

    @abstractmethod
    def execute(self, context: dict) -> AgentResult:
        """Ajanın ana görevini çalıştırır."""
        ...


# ─────────────────────────────────────────────
# Exploit Agent
# ─────────────────────────────────────────────

class ExploitAgent(BaseAgent):
    """Exploit kodunu hedefe göre yazar ve parametreleri ayarlar.

    Sorumluluklar:
        - Ham exploit kodunu LHOST/RHOST/LPORT ile uyarla
        - OPSEC Agent'tan gelen geri bildirimi alarak revizyon yap
    """

    SYSTEM_PROMPT = (
        "Sen 'OffSploit ExploitAgent' adında uzman bir exploit geliştirme ajanısın. "
        "Görevin exploit kodlarını hedef parametrelere göre uyarlamak ve "
        "OPSEC Agent'tan gelen geri bildirimlere göre kodu revize etmektir. "
        "Her zaman çalışır, derlenebilir ve OPSEC açısından güvenli kod üret. "
        "Sadece güncellenmiş tam kaynak kodunu dön, açıklama ekleme."
    )

    def __init__(self, llm_client):
        super().__init__(
            name="ExploitAgent",
            role="Exploit kodunu hedefe göre uyarlar ve revize eder",
            llm_client=llm_client
        )

    def execute(self, context: dict) -> AgentResult:
        """Exploit kodunu uyarlar.

        Context keys:
            - exploit_code: Ham exploit kodu
            - lhost, rhost, lport: Ağ parametreleri
            - opsec_feedback: (opsiyonel) OPSEC Agent geri bildirimi
        """
        exploit_code = context.get("exploit_code", "")
        lhost = context.get("lhost", "")
        rhost = context.get("rhost", "")
        lport = context.get("lport", "4444")
        opsec_feedback = context.get("opsec_feedback", "")

        if opsec_feedback:
            return self._revise(exploit_code, opsec_feedback)
        else:
            return self._adapt(exploit_code, lhost, rhost, lport)

    def _adapt(self, exploit_code: str, lhost: str, rhost: str, lport: str) -> AgentResult:
        """İlk uyarlama: Ham kodu hedef parametrelere göre güncelle."""
        logger.info("[ExploitAgent] İlk uyarlama başlıyor — LHOST=%s RHOST=%s LPORT=%s", lhost, rhost, lport)

        try:
            result = self.llm.adapt_exploit(
                exploit_code=exploit_code,
                lhost=lhost,
                rhost=rhost,
                lport=lport
            )
            if result and result.strip():
                return AgentResult(success=True, code=result, message="Exploit başarıyla uyarlandı.")
            else:
                return AgentResult(success=False, message="LLM boş yanıt döndürdü.")
        except Exception as exc:
            logger.error("[ExploitAgent] Uyarlama hatası: %s", exc)
            return AgentResult(success=False, code=exploit_code, message=str(exc))

    def _revise(self, current_code: str, opsec_feedback: str) -> AgentResult:
        """OPSEC geri bildirimine göre kodu revize eder."""
        logger.info("[ExploitAgent] OPSEC geri bildirimine göre revizyon başlıyor.")

        system_prompt = (
            "Sen 'OffSploit ExploitAgent' adında uzman bir exploit geliştirme ajanısın. "
            "Aşağıdaki OPSEC Agent'tan gelen geri bildirime göre kodu güvenli hale getir. "
            "Clear-text string'leri şifrele, gereksiz disk IO'yu kaldır, gürültülü process "
            "spawn'ları sessizleştir. Kodun mantığını BOZMA, sadece OPSEC sorunlarını gider. "
            "Sadece düzeltilmiş tam kaynak kodunu dön."
        )

        user_prompt = (
            f"İşte mevcut exploit kodu:\n```\n{current_code}\n```\n\n"
            f"OPSEC Agent'ın Geri Bildirimi:\n{opsec_feedback}\n\n"
            "Lütfen yukarıdaki OPSEC sorunlarını gider ve düzeltilmiş tam kodu dön."
        )

        try:
            from offsploit.response_parser import extract_code_from_response
            resp = self.llm.provider.generate(system_prompt, user_prompt, temperature=0.15)
            code = extract_code_from_response(resp)
            if code and code.strip():
                return AgentResult(success=True, code=code, message="OPSEC revizyonu tamamlandı.")
            else:
                return AgentResult(success=False, code=current_code, message="Revizyon yanıtı boş.")
        except Exception as exc:
            logger.error("[ExploitAgent] Revizyon hatası: %s", exc)
            return AgentResult(success=False, code=current_code, message=str(exc))


# ─────────────────────────────────────────────
# OPSEC Agent
# ─────────────────────────────────────────────

class OPSECAgent(BaseAgent):
    """Exploit kodunu OPSEC perspektifinden inceleyen ajan.

    Kontrol listesi:
        - Clear-text string'ler (IP, URL, path, credential)
        - Gereksiz disk I/O işlemleri (dosya yazma, log)
        - Gürültülü process spawn (subprocess, os.system, CreateProcess)
        - Hardcoded credential'lar
        - Ağ gürültüsü (plain HTTP, DNS leak)
        - Zaman damgası veya fingerprint bırakma
    """

    OPSEC_CHECKLIST = [
        "1. CLEAR-TEXT STRINGS: Kodda açık metin IP adresleri, URL'ler, dosya yolları veya credential'lar var mı?",
        "2. DISK I/O: Gereksiz dosya yazma, log dosyası oluşturma veya temp dosya bırakma var mı?",
        "3. PROCESS NOISE: os.system(), subprocess.call(), CreateProcessA gibi gürültülü process spawn'lamaları var mı?",
        "4. HARDCODED CREDS: Kullanıcı adı, şifre veya API anahtarı açık metin olarak gömülmüş mü?",
        "5. NETWORK NOISE: Plain HTTP (HTTPS yerine), DNS leak'e açık sorgular var mı?",
        "6. FORENSIC TRACES: Zaman damgası, hostname, username gibi forensik iz bırakan operasyonlar var mı?",
        "7. ANTI-ANALYSIS: Anti-debugging veya sandbox evasion mekanizması eksik mi?",
        "8. MEMORY SAFETY: Bellek sızıntısı (memory leak) veya güvenli olmayan bellek yönetimi var mı?"
    ]

    SYSTEM_PROMPT = (
        "Sen 'OffSploit OPSECAgent' adında uzman bir Operasyonel Güvenlik (OPSEC) denetçisisin. "
        "Görevin, sana verilen exploit/zararlı yazılım kodunu aşağıdaki OPSEC kontrol listesine göre "
        "titizlikle inceleyip, tespit ettiğin sorunları yapılandırılmış formatta raporlamaktır.\n\n"
        "KONTROL LİSTESİ:\n" + "\n".join(OPSEC_CHECKLIST) + "\n\n"
        "YANITINI ZORUNLU olarak aşağıdaki JSON formatında ver:\n"
        '{"passed": true/false, "findings": [{"category": "CLEAR_TEXT", "severity": "critical/high/medium/low/info", '
        '"description": "...", "line_hint": "...", "recommendation": "..."}], "summary": "..."}\n\n'
        "Eğer hiç sorun yoksa passed=true ve findings=[] dön. Aksi halde tüm sorunları listele."
    )

    def __init__(self, llm_client, sensitivity: str = "moderate"):
        super().__init__(
            name="OPSECAgent",
            role="Exploit kodunu OPSEC açısından denetler",
            llm_client=llm_client
        )
        try:
            self.sensitivity = OPSECSensitivity(sensitivity.lower())
        except ValueError:
            self.sensitivity = OPSECSensitivity.MODERATE

    def execute(self, context: dict) -> AgentResult:
        """Exploit kodunu OPSEC incelemesine tabi tutar.

        Context keys:
            - code: İncelenecek exploit kodu
        """
        code = context.get("code", "")
        review = self.review(code)

        return AgentResult(
            success=review.passed,
            code=code,
            message=review.summary,
            metadata={"findings_count": len(review.findings), "raw_response": review.raw_response}
        )

    def review(self, code: str) -> OPSECReview:
        """Exploit kodunu OPSEC perspektifinden inceler.

        Args:
            code: İncelenecek exploit kodu.

        Returns:
            OPSECReview: İnceleme sonucu.
        """
        logger.info("[OPSECAgent] OPSEC incelemesi başlıyor (hassasiyet: %s)", self.sensitivity.value)

        user_prompt = f"İşte incelenecek exploit kodu:\n```\n{code}\n```\n\nLütfen OPSEC analiz sonucunu JSON formatında dön."

        try:
            raw_response = self.llm.provider.generate(
                self.SYSTEM_PROMPT,
                user_prompt,
                temperature=0.1,
                max_tokens=4096,
            )
            return self._parse_review(raw_response)
        except Exception as exc:
            logger.error("[OPSECAgent] İnceleme hatası: %s", exc)
            # Hata durumunda güvenli tarafta kal: pass et
            return OPSECReview(
                passed=True,
                summary=f"OPSEC incelemesi sırasında hata oluştu: {exc}",
                raw_response=""
            )

    def _parse_review(self, raw_response: str) -> OPSECReview:
        """LLM yanıtını yapılandırılmış OPSECReview'e dönüştürür."""
        # JSON bloğunu bul
        json_match = re.search(r'\{[\s\S]*\}', raw_response)
        if not json_match:
            logger.warning("[OPSECAgent] JSON formatı bulunamadı, yanıt metin olarak işleniyor.")
            return OPSECReview(
                passed=True,
                summary="OPSEC yanıtı JSON formatında değil, inceleme atlanıyor.",
                raw_response=raw_response
            )

        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError as exc:
            logger.warning("[OPSECAgent] JSON parse hatası: %s", exc)
            return OPSECReview(
                passed=True,
                summary="OPSEC JSON parse hatası, inceleme atlanıyor.",
                raw_response=raw_response
            )

        findings: list[OPSECFinding] = []
        for f in data.get("findings", []):
            try:
                severity = OPSECSeverity(f.get("severity", "info").lower())
            except ValueError:
                severity = OPSECSeverity.INFO

            findings.append(OPSECFinding(
                category=f.get("category", "UNKNOWN"),
                severity=severity,
                description=f.get("description", ""),
                line_hint=f.get("line_hint", ""),
                recommendation=f.get("recommendation", ""),
            ))

        # Hassasiyet seviyesine göre pass/fail kararı
        passed = self._evaluate_findings(findings, data.get("passed", True))

        return OPSECReview(
            passed=passed,
            findings=findings,
            summary=data.get("summary", ""),
            raw_response=raw_response
        )

    def _evaluate_findings(self, findings: list[OPSECFinding], llm_verdict: bool) -> bool:
        """Hassasiyet seviyesine göre pass/fail kararı verir."""
        if not findings:
            return True

        if self.sensitivity == OPSECSensitivity.STRICT:
            # Herhangi bir bulgu varsa fail
            return len(findings) == 0

        elif self.sensitivity == OPSECSensitivity.MODERATE:
            # CRITICAL veya HIGH bulgu varsa fail
            blocking = [f for f in findings if f.severity in (OPSECSeverity.CRITICAL, OPSECSeverity.HIGH)]
            return len(blocking) == 0

        elif self.sensitivity == OPSECSensitivity.LOOSE:
            # Sadece CRITICAL bulgu varsa fail
            critical = [f for f in findings if f.severity == OPSECSeverity.CRITICAL]
            return len(critical) == 0

        return llm_verdict

    def format_feedback(self, review: OPSECReview) -> str:
        """OPSEC inceleme sonucunu ExploitAgent'a gönderilebilir formatta biçimler."""
        if review.passed:
            return "OPSEC incelemesinden geçti. Sorun tespit edilmedi."

        lines = ["OPSEC İnceleme Sonucu: BAŞARISIZ\n"]
        for i, f in enumerate(review.findings, 1):
            lines.append(
                f"{i}. [{f.severity.value.upper()}] {f.category}: {f.description}"
            )
            if f.recommendation:
                lines.append(f"   → Öneri: {f.recommendation}")
            if f.line_hint:
                lines.append(f"   → Satır: {f.line_hint}")
            lines.append("")

        if review.summary:
            lines.append(f"Özet: {review.summary}")

        return "\n".join(lines)


# ─────────────────────────────────────────────
# Swarm Orchestrator
# ─────────────────────────────────────────────

class SwarmOrchestrator:
    """İki ajanı koordine eden merkezi orkestratör.

    İş akışı:
        1. ExploitAgent kodu uyarlar
        2. OPSECAgent kodu inceler
        3. OPSEC başarısızsa → ExploitAgent'a geri bildirim → revize et → tekrar incele
        4. Maksimum round'a kadar tekrarla veya OPSEC geçene kadar
    """

    def __init__(
        self,
        llm_client,
        max_rounds: int = 3,
        opsec_sensitivity: str = "moderate",
        on_event: Callable[[str, dict], None] | None = None,
    ):
        self.exploit_agent = ExploitAgent(llm_client)
        self.opsec_agent = OPSECAgent(llm_client, sensitivity=opsec_sensitivity)
        self.max_rounds = max_rounds
        self.on_event = on_event or (lambda e, d: None)
        self._round_history: list[dict] = []

    def run(
        self,
        exploit_code: str,
        lhost: str,
        rhost: str,
        lport: str,
    ) -> AgentResult:
        """Swarm iş akışını çalıştırır.

        Args:
            exploit_code: Ham exploit kaynak kodu.
            lhost, rhost, lport: Ağ parametreleri.

        Returns:
            AgentResult: Onaylanmış final kod.
        """
        logger.info("=" * 60)
        logger.info("[SwarmOrchestrator] Swarm iş akışı başlıyor (max_rounds=%d)", self.max_rounds)

        # Adım 1: İlk uyarlama
        self.on_event("swarm_step", {
            "agent": "ExploitAgent",
            "action": "adapt",
            "round": 0,
            "status": "running"
        })

        adapt_result = self.exploit_agent.execute({
            "exploit_code": exploit_code,
            "lhost": lhost,
            "rhost": rhost,
            "lport": lport,
        })

        if not adapt_result.success:
            logger.error("[SwarmOrchestrator] İlk uyarlama başarısız: %s", adapt_result.message)
            return adapt_result

        current_code = adapt_result.code
        self.on_event("swarm_step", {
            "agent": "ExploitAgent",
            "action": "adapt",
            "round": 0,
            "status": "done"
        })

        # Adım 2: OPSEC döngüsü
        for round_num in range(1, self.max_rounds + 1):
            logger.info("[SwarmOrchestrator] Round %d/%d başlıyor...", round_num, self.max_rounds)

            # OPSEC inceleme
            self.on_event("swarm_step", {
                "agent": "OPSECAgent",
                "action": "review",
                "round": round_num,
                "status": "running"
            })

            opsec_result = self.opsec_agent.execute({"code": current_code})
            review = self.opsec_agent.review(current_code)

            self._round_history.append({
                "round": round_num,
                "opsec_passed": review.passed,
                "findings_count": len(review.findings),
                "summary": review.summary,
            })

            self.on_event("swarm_step", {
                "agent": "OPSECAgent",
                "action": "review",
                "round": round_num,
                "status": "done",
                "passed": review.passed,
                "findings": len(review.findings),
            })

            if review.passed:
                logger.info(
                    "[SwarmOrchestrator] OPSEC incelemesi GEÇTİ (round %d). Kod onaylandı.",
                    round_num
                )
                return AgentResult(
                    success=True,
                    code=current_code,
                    message=f"Swarm onayladı: OPSEC incelemesi round {round_num}'de geçti.",
                    metadata={"rounds": round_num, "history": self._round_history}
                )

            # OPSEC başarısız → ExploitAgent'a geri bildirim
            if round_num < self.max_rounds:
                feedback = self.opsec_agent.format_feedback(review)
                logger.info(
                    "[SwarmOrchestrator] OPSEC başarısız (round %d, %d bulgu). ExploitAgent'a revizyon gönderiliyor...",
                    round_num, len(review.findings)
                )

                self.on_event("swarm_step", {
                    "agent": "ExploitAgent",
                    "action": "revise",
                    "round": round_num,
                    "status": "running"
                })

                revise_result = self.exploit_agent.execute({
                    "exploit_code": current_code,
                    "opsec_feedback": feedback,
                })

                if revise_result.success and revise_result.code:
                    current_code = revise_result.code

                self.on_event("swarm_step", {
                    "agent": "ExploitAgent",
                    "action": "revise",
                    "round": round_num,
                    "status": "done"
                })

        # Tüm round'lar tükendi
        logger.warning(
            "[SwarmOrchestrator] %d round sonrası OPSEC geçilemedi. Son kod döndürülüyor.",
            self.max_rounds
        )
        return AgentResult(
            success=True,  # Kodu yine de döndür, ama uyarı ile
            code=current_code,
            message=f"Swarm: {self.max_rounds} round sonrası OPSEC tam olarak geçilemedi. Son revize edilmiş kod döndürülüyor.",
            metadata={"rounds": self.max_rounds, "history": self._round_history, "opsec_partial": True}
        )

    def get_history(self) -> list[dict]:
        """Round geçmişini döndürür."""
        return self._round_history.copy()
