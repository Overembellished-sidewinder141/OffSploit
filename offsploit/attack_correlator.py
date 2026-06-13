#!/usr/bin/env python3
"""
OffSploit - Çoklu Vektör Saldırı Korelasyonu v1.0
====================================================
Nmap servis zafiyetleri ile BloodHound Active Directory yetki yollarını
birleştirerek LLM'in zincirleme saldırı yolları (Attack Paths)
çıkarmasını sağlayan korelasyon modülü.
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("offsploit.correlator")


@dataclass
class ServiceVulnerability:
    """Bir servis için tespit edilen zafiyet."""
    query: str
    port: int = 0
    protocol: str = "tcp"
    exploit_description: str = ""
    exploit_type: str = ""
    platform: str = ""
    distance: float = 999.0


@dataclass
class ADPath:
    """Active Directory saldırı yolu."""
    steps: list[tuple[str, str, str]] = field(default_factory=list)  # (source, relation, target)
    start_node: str = ""
    end_node: str = ""

    def to_string(self) -> str:
        if not self.steps:
            return "Yol bulunamadı."
        lines = []
        for i, (src, rel, tgt) in enumerate(self.steps, 1):
            lines.append(f"  {i}. [{src}] --({rel})--> [{tgt}]")
        return "\n".join(lines)


@dataclass
class AttackChain:
    """Birleştirilmiş zincirleme saldırı zinciri."""
    name: str
    phases: list[str] = field(default_factory=list)
    vulnerabilities: list[ServiceVulnerability] = field(default_factory=list)
    ad_paths: list[ADPath] = field(default_factory=list)
    llm_plan: str = ""
    risk_score: float = 0.0


@dataclass
class CorrelationResult:
    """Korelasyon çıktısı."""
    success: bool
    attack_chains: list[AttackChain] = field(default_factory=list)
    summary: str = ""
    raw_context: str = ""


class AttackCorrelator:
    """Nmap + BloodHound verilerini birleştirerek zincirleme saldırı planı üreten korelasyon motoru.

    İş akışı:
        1. RAG'dan servis zafiyetlerini çek
        2. BloodHound'dan AD yetki yollarını çek
        3. İkisini birleştirip LLM'e zincirleme saldırı planı ürettir
    """

    CORRELATION_SYSTEM_PROMPT = (
        "Sen uzman bir Red Team stratejistisin. Sana iki farklı veri kaynağı verilecek:\n"
        "1. NMAP tabanlı servis zafiyetleri (exploit'ler)\n"
        "2. BloodHound tabanlı Active Directory yetki yolları (attack paths)\n\n"
        "Görevin, bu iki veri kaynağını birleştirerek çok aşamalı (multi-stage) "
        "zincirleme saldırı planları oluşturmaktır. Her plan:\n"
        "- İlk erişim (Initial Access) → servis zafiyetinden yararlanma\n"
        "- Yetki yükseltme (Privilege Escalation) → AD yetki yollarından yararlanma\n"
        "- Yanal hareket (Lateral Movement) → komşu sistemlere geçiş\n"
        "- Hedef (Objective) → Domain Admin veya kritik varlık ele geçirme\n\n"
        "Her adım için SOMUT, ÇALIŞTIRILABİLİR komutlar ve araçlar (Mimikatz, Rubeus, "
        "CrackMapExec, Impacket vb.) belirt. Markdown formatında, numaralı adımlar halinde yaz."
    )

    def __init__(self, llm_client, rag_engine=None):
        self.llm = llm_client
        self.rag = rag_engine

    def correlate(
        self,
        service_vulns: list[ServiceVulnerability],
        ad_paths: list[ADPath],
        target_ip: str = "",
    ) -> CorrelationResult:
        """Servis zafiyetleri + AD yetki yollarını birleştirerek saldırı planı üretir.

        Args:
            service_vulns: Nmap + RAG'dan gelen servis zafiyetleri.
            ad_paths: BloodHound'dan gelen AD saldırı yolları.
            target_ip: Hedef IP adresi.

        Returns:
            CorrelationResult: Zincirleme saldırı planları.
        """
        logger.info(
            "[AttackCorrelator] Korelasyon başlıyor — %d zafiyet, %d AD yolu",
            len(service_vulns), len(ad_paths)
        )

        # Birleştirilmiş context oluştur
        context = self._build_context(service_vulns, ad_paths, target_ip)

        if not context.strip():
            return CorrelationResult(
                success=False,
                summary="Korelasyon için yeterli veri yok.",
            )

        # LLM'e gönder
        try:
            user_prompt = (
                f"Hedef: {target_ip}\n\n"
                f"{context}\n\n"
                "Lütfen yukarıdaki verileri analiz ederek mümkün olan tüm "
                "zincirleme saldırı yollarını planla."
            )

            resp = self.llm.provider.generate(
                self.CORRELATION_SYSTEM_PROMPT,
                user_prompt,
                temperature=0.3,
                max_tokens=8192,
            )

            # Saldırı zincirlerini parse et
            chains = self._parse_attack_chains(resp, service_vulns, ad_paths)

            return CorrelationResult(
                success=True,
                attack_chains=chains,
                summary=f"{len(chains)} zincirleme saldırı yolu tespit edildi.",
                raw_context=context,
            )

        except Exception as exc:
            logger.error("[AttackCorrelator] Korelasyon hatası: %s", exc)
            return CorrelationResult(
                success=False,
                summary=f"Korelasyon hatası: {exc}",
                raw_context=context,
            )

    def _build_context(
        self,
        service_vulns: list[ServiceVulnerability],
        ad_paths: list[ADPath],
        target_ip: str,
    ) -> str:
        """LLM'e gönderilecek birleştirilmiş context'i oluşturur."""
        parts: list[str] = []

        # Servis zafiyetleri
        if service_vulns:
            parts.append("═" * 50)
            parts.append("📡 SERVİS ZAFİYETLERİ (Nmap + ExploitDB)")
            parts.append("═" * 50)
            for i, vuln in enumerate(service_vulns, 1):
                parts.append(
                    f"{i}. Port {vuln.port}/{vuln.protocol}: {vuln.query}\n"
                    f"   Exploit: {vuln.exploit_description}\n"
                    f"   Tür: {vuln.exploit_type} | Platform: {vuln.platform} | "
                    f"Güven: {vuln.distance:.4f}"
                )
            parts.append("")

        # AD yetki yolları
        if ad_paths:
            parts.append("═" * 50)
            parts.append("🏰 ACTIVE DIRECTORY YETKİ YOLLARI (BloodHound)")
            parts.append("═" * 50)
            for i, path in enumerate(ad_paths, 1):
                parts.append(f"Yol {i}: {path.start_node} → {path.end_node}")
                parts.append(path.to_string())
                parts.append("")

        # RAG'dan AD ilişkili ek context
        if self.rag:
            try:
                ad_context = self.rag.search_ad("privilege escalation domain admin", top_k=3)
                if ad_context:
                    parts.append("═" * 50)
                    parts.append("🔍 RAG EK CONTEXT (AD İlişkili)")
                    parts.append("═" * 50)
                    for ctx in ad_context:
                        parts.append(f"- {ctx.get('document', '')[:200]}")
                    parts.append("")
            except Exception:
                pass

        return "\n".join(parts)

    def _parse_attack_chains(
        self,
        llm_response: str,
        service_vulns: list[ServiceVulnerability],
        ad_paths: list[ADPath],
    ) -> list[AttackChain]:
        """LLM yanıtından saldırı zincirlerini çıkarır."""
        # Basit bir chain oluştur (LLM'in tüm yanıtını tek chain olarak sarmalama)
        chain = AttackChain(
            name="Primary Attack Chain",
            vulnerabilities=service_vulns,
            ad_paths=ad_paths,
            llm_plan=llm_response,
            risk_score=self._calculate_risk(service_vulns, ad_paths),
        )

        # Fazları LLM yanıtından çıkarmaya çalış
        phases = []
        for keyword in ["Initial Access", "İlk Erişim", "Privilege Escalation",
                        "Yetki Yükseltme", "Lateral Movement", "Yanal Hareket",
                        "Persistence", "Kalıcılık", "Objective", "Hedef"]:
            if keyword.lower() in llm_response.lower():
                phases.append(keyword)

        chain.phases = phases if phases else ["Multi-Stage Attack"]

        return [chain]

    def _calculate_risk(
        self,
        service_vulns: list[ServiceVulnerability],
        ad_paths: list[ADPath],
    ) -> float:
        """Basit risk skoru hesaplar (0-10 arası)."""
        score = 0.0

        # Düşük distance = yüksek risk
        if service_vulns:
            avg_distance = sum(v.distance for v in service_vulns) / len(service_vulns)
            score += max(0, (1.0 - avg_distance) * 5)

        # AD yolu varsa = yüksek risk
        if ad_paths:
            score += min(5.0, len(ad_paths) * 2.5)

        return min(10.0, score)

    def generate_attack_plan(
        self,
        service_vulns: list[ServiceVulnerability],
        ad_paths: list[ADPath],
        target_ip: str = "",
    ) -> str:
        """Zincirleme saldırı planını düz metin olarak üretir.

        LLM'in tüm bağlamı görerek kapsamlı bir plan yazmasını sağlar.
        """
        result = self.correlate(service_vulns, ad_paths, target_ip)
        if result.success and result.attack_chains:
            return result.attack_chains[0].llm_plan
        return result.summary
