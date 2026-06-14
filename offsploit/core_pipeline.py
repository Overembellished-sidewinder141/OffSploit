#!/usr/bin/env python3
"""
OffSploit - Core Pipeline v1.0
================================
Nmap XML tarama dosyasından başlayıp exploit'in bulunması,
Multi-Agent Swarm ile uyarlanması, Docker Sandbox'ta derlenmesi,
Evasion/Payload enjeksiyonu ve State Machine kaydı sağlayan
merkezi iş akışı sınıfı.
"""

import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from offsploit.llm_client import LLMClient
from offsploit.nmap_parser import NmapParser
from offsploit.rag_engine import OffSploitRAG

logger = logging.getLogger("offsploit.pipeline")


class OffSploitPipeline:
    """Merkezi saldırı pipeline'ı v1.0.

    Yeni özellikler:
        - Multi-Agent Swarm (ExploitAgent + OPSECAgent)
        - Docker Sandbox self-healing
        - Polimorfik Evasion Engine
        - Post-Exploitation Payload Engine
        - Attack Correlator (BloodHound + Nmap)
        - Otonom Pivoting State Machine
    """

    def __init__(self, config: dict[str, Any] | Any, on_event: Callable[[str, dict], None], cancel_check: Callable[[], bool] = None):
        # OffSploitConfig veya dict kabul et (geriye uyumluluk)
        if hasattr(config, "to_dict"):
            # OffSploitConfig nesnesi
            self.config = config.to_dict()
        elif isinstance(config, dict):
            self.config = config
        else:
            self.config = dict(config)
        self.on_event = on_event
        self.cancel_check = cancel_check or (lambda: False)

    def _emit(self, event_type: str, data: dict = None):
        if data is None:
            data = {}
        self.on_event(event_type, data)

    def run(
        self,
        nmap_path: str,
        lhost: str,
        rhost: str,
        lport: str,
        model: str,
        top_k: int,
        obfuscate: bool = False,
        fileless: bool = False,
        ghost: bool = False,
        evasion: bool = False,
        evasion_level: str = "advanced",
        payload_inject: bool = False,
        payload_type: str = "reverse_tcp",
        use_swarm: bool | None = None,
        use_docker: bool | None = None,
    ):
        str(uuid.uuid4())[:8]
        cfg = self.config

        # Feature flag'leri config'den al (eğer parametre verilmemişse)
        if use_swarm is None:
            use_swarm = cfg.get("use_swarm", False)
        if use_docker is None:
            use_docker = cfg.get("use_docker_sandbox", False)

        successful_exploits = []

        try:
            # ════════════════════════════════════════════
            # ADIM 1: Nmap Analizi
            # ════════════════════════════════════════════
            self._emit("step_start", {"step": 1, "name": "Adım 1: Nmap Sonuçlarının Analizi"})

            if not nmap_path or not Path(nmap_path).exists():
                self._emit("step_warning", {"step": 1, "name": "Adım 1: Nmap Sonuçlarının Analizi", "message": f"Nmap dosyası bulunamadı: {nmap_path}"})
                self._emit("complete", {"success": False, "message": f"Nmap dosyası eksik: {nmap_path}"})
                return

            parser = NmapParser(nmap_path)
            services = parser.parse()

            if not services:
                self._emit("step_warning", {"step": 1, "name": "Adım 1: Nmap Sonuçlarının Analizi", "message": "Hedefte açık servis tespit edilemedi."})
                self._emit("complete", {"success": False, "message": "Açık servis bulunamadığı için işlem durduruldu."})
                return

            service_data = [{"port": s.port, "protocol": s.protocol, "query": s.query, "name": s.name, "product": s.product, "version": s.version} for s in services]
            self._emit("step_done", {"step": 1, "name": "Adım 1: Nmap Sonuçlarının Analizi", "data": service_data})

            if self.cancel_check(): return self._handle_cancel()

            # ════════════════════════════════════════════
            # ADIM 2: Pre-Flight Check
            # ════════════════════════════════════════════
            self._emit("step_start", {"step": 1.5, "name": "Adım 2: Hedef Erişilebilirlik Kontrolü (Pre-Flight Check)"})
            skip_preflight = cfg.get("skip_preflight", False)

            if skip_preflight:
                self._emit("step_done", {"step": 1.5, "name": "Adım 2: Hedef Erişilebilirlik Kontrolü (Pre-Flight Check)", "data": {"message": "--skip-preflight parametresi ile atlandı."}})
            elif rhost:
                from offsploit.preflight import PreFlightCheck
                test_port = int(services[0].port) if services else 80
                is_alive, msg = PreFlightCheck.check_target_alive(rhost, test_port)
                if not is_alive:
                    self._emit("step_warning", {"step": 1.5, "name": "Adım 2: Hedef Erişilebilirlik Kontrolü (Pre-Flight Check)", "message": f"Hedef sisteme ulaşılamıyor: {msg}"})
                    self._emit("complete", {"success": False, "message": f"Bağlantı kurulamadı: {msg}"})
                    return
                else:
                    self._emit("step_done", {"step": 1.5, "name": "Adım 2: Hedef Erişilebilirlik Kontrolü (Pre-Flight Check)", "data": {"message": msg}})
            else:
                self._emit("step_done", {"step": 1.5, "name": "Adım 2: Hedef Erişilebilirlik Kontrolü (Pre-Flight Check)", "data": {"message": "RHOST verilmediği için test atlandı."}})

            if self.cancel_check(): return self._handle_cancel()

            # ════════════════════════════════════════════
            # ADIM 3: Semantik Zafiyet Taraması (RAG v1)
            # ════════════════════════════════════════════
            self._emit("step_start", {"step": 2, "name": "Adım 3: Semantik Zafiyet (Exploit) Taraması"})
            db_path = cfg.get("chromadb_path", cfg.get("db_path"))
            rag = OffSploitRAG(
                db_path=db_path,
                exploitdb_root=cfg["exploitdb_root"],
                top_k=top_k,
                config=cfg,  # v1: Config ile embedding provider seçimi
            )
            queries = [s.query for s in services]
            all_results = rag.search_multiple(queries)

            # TRIAGE: Sadece distance < 0.6 ve DOS olmayanları filtrele
            filtered_matches = []
            distance_threshold = 0.6

            for q, matches in all_results.items():
                best_match = None
                for m in matches:
                    is_dos = "dos" in m.exploit_type.lower() or "denial of service" in m.description.lower()
                    if m.source_code and m.distance <= distance_threshold and not is_dos:
                        if best_match is None or m.distance < best_match.distance:
                            best_match = m

                if best_match:
                    filtered_matches.append({
                        "query": q,
                        "match": best_match
                    })

            if not filtered_matches:
                self._emit("step_warning", {"step": 2, "name": "Adım 3: Semantik Zafiyet (Exploit) Taraması", "message": "Güvenlik eşiğini karşılayan (non-DoS) exploit bulunamadı."})
                self._emit("complete", {"success": False, "message": "Uygun zafiyet bulunamadı."})
                return

            self._emit("step_done", {"step": 2, "name": "Adım 3: Semantik Zafiyet (Exploit) Taraması", "data": {"count": len(filtered_matches)}})

            if self.cancel_check(): return self._handle_cancel()

            # ════════════════════════════════════════════
            # LLM ve Modül Başlatma
            # ════════════════════════════════════════════
            output_dir = Path(cfg["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)

            llm = None
            if lhost and rhost:
                try:
                    llm = LLMClient(
                        provider=cfg.get("llm_provider", "ollama"),
                        ollama_url=cfg.get("ollama_url", "http://localhost:11434"),
                        ollama_model=model,
                        ollama_timeout=int(cfg.get("ollama_timeout", 300)),
                        api_key=cfg.get("api_key", "")
                    )
                except Exception as e:
                    logger.error("LLM init hatasi: %s", e)

            # Docker Sandbox init (lazy)
            docker_sandbox = None
            if use_docker and llm:
                try:
                    from offsploit.docker_sandbox import DockerSandbox
                    sandbox = DockerSandbox(
                        memory_limit=cfg.get("docker_memory_limit", "256m"),
                        cpu_limit=float(cfg.get("docker_cpu_limit", 0.5)),
                        timeout=int(cfg.get("docker_timeout", 30)),
                    )
                    if sandbox.is_available():
                        docker_sandbox = sandbox
                        logger.info("Docker sandbox aktif.")
                    else:
                        logger.warning("Docker daemon erişilebilir değil, CompilerAgent fallback kullanılacak.")
                except Exception as e:
                    logger.warning("Docker sandbox başlatılamadı: %s. Fallback kullanılacak.", e)

            # Swarm Orchestrator init (lazy)
            swarm = None
            if use_swarm and llm:
                try:
                    from offsploit.swarm_agents import SwarmOrchestrator
                    swarm = SwarmOrchestrator(
                        llm_client=llm,
                        max_rounds=int(cfg.get("swarm_max_rounds", 3)),
                        opsec_sensitivity=cfg.get("opsec_sensitivity", "moderate"),
                        on_event=self._emit,
                    )
                    logger.info("Swarm Orchestrator aktif (max_rounds=%d).", swarm.max_rounds)
                except Exception as e:
                    logger.warning("Swarm init hatası: %s. Eski adaptasyon yöntemi kullanılacak.", e)

            # ════════════════════════════════════════════
            # Multi-Target Loop
            # ════════════════════════════════════════════
            for idx, item in enumerate(filtered_matches):
                if self.cancel_check(): return self._handle_cancel()

                query = item["query"]
                match = item["match"]

                logger.info(f"Exploit İşleniyor ({idx+1}/{len(filtered_matches)}): {query}")

                # ────────────────────────────────────────
                # ADIM 4: LLM Adaptasyonu (Swarm veya Klasik)
                # ────────────────────────────────────────
                self._emit("step_start", {"step": 3, "name": f"Adım 4: LLM Exploit Uyarlaması ({query})"})
                adapted_code = match.source_code
                compiler_msg = ""

                if swarm:
                    # Swarm: ExploitAgent + OPSECAgent döngüsü
                    logger.info("[Swarm] Multi-Agent OPSEC uyarlaması başlıyor...")
                    try:
                        swarm_result = swarm.run(
                            exploit_code=match.source_code,
                            lhost=lhost,
                            rhost=rhost,
                            lport=lport,
                        )
                        if swarm_result.success and swarm_result.code:
                            adapted_code = swarm_result.code
                            rounds = swarm_result.metadata.get("rounds", 0)
                            opsec_partial = swarm_result.metadata.get("opsec_partial", False)
                            compiler_msg = f"Swarm: {rounds} round"
                            if opsec_partial:
                                compiler_msg += " [OPSEC_PARTIAL]"
                            else:
                                compiler_msg += " [OPSEC_PASS]"
                    except Exception as e:
                        logger.error("Swarm hatası: %s. Klasik adaptasyona fallback.", e)
                        if llm:
                            try:
                                result = llm.adapt_exploit(exploit_code=match.source_code, lhost=lhost, rhost=rhost, lport=lport)
                                if result:
                                    adapted_code = result
                            except Exception as llm_err:
                                logger.error("LLM hatası (%s): %s", query, llm_err)
                elif llm:
                    # Klasik adaptasyon
                    try:
                        result = llm.adapt_exploit(exploit_code=match.source_code, lhost=lhost, rhost=rhost, lport=lport)
                        if result:
                            adapted_code = result
                    except Exception as llm_err:
                        logger.error("LLM hatası (%s): %s", query, llm_err)

                self._emit("step_done", {"step": 3, "name": f"Adım 4: LLM Exploit Uyarlaması ({query})", "data": {"length": len(adapted_code)}})

                # ────────────────────────────────────────
                # ADIM 5: Derleme (Docker Sandbox veya CompilerAgent)
                # ────────────────────────────────────────
                self._emit("step_start", {"step": 3.5, "name": f"Adım 5: Derleme ve Syntax Kontrolü ({query})"})
                ext_map = {".c": "C", ".cpp": "C++", ".py": "Python", ".rb": "Ruby", ".pl": "Perl", ".sh": "Bash"}
                suffix = Path(match.file_path).suffix.lower()
                lang = ext_map.get(suffix, "Bilinmeyen Dil")

                if not compiler_msg:
                    compiler_msg = f"{lang} derleme kontrolü."

                if lang in ["C", "C++", "Python"] and llm:
                    if docker_sandbox:
                        # Docker Sandbox Self-Healing
                        logger.info("Docker Sandbox self-healing döngüsü başlıyor (%s)...", lang)
                        success, adapted_code, sandbox_msg = docker_sandbox.self_healing_loop(
                            source_code=adapted_code,
                            language=lang.lower().replace("c++", "cpp"),
                            llm_fix_callback=llm.fix_exploit,
                            max_retries=2,
                        )
                        compiler_msg = f"[DOCKER] {sandbox_msg}"
                    else:
                        # CompilerAgent Fallback
                        from offsploit.compiler_agent import CompilerAgent
                        max_retries = 2
                        attempt = 0
                        while attempt <= max_retries:
                            if lang == "Python":
                                success_compile, msg, _ = CompilerAgent.check_python_syntax(adapted_code)
                                if success_compile:
                                    success_logic, logic_msg, _ = CompilerAgent.check_python_logic(adapted_code)
                                    if not success_logic:
                                        success_compile = False
                                        msg = logic_msg
                                    else:
                                        msg = f"{msg} ve {logic_msg}"
                            else:
                                success_compile, msg, _ = CompilerAgent.compile_and_check(adapted_code, language=lang)

                            compiler_msg = msg
                            if success_compile:
                                break
                            else:
                                if attempt < max_retries:
                                    logger.info("%s hatası tespit edildi. LLM üzerinden onarılıyor... (Deneme %d)", lang, attempt+1)
                                    try:
                                        fixed_code = llm.fix_exploit(adapted_code, msg)
                                        if fixed_code:
                                            adapted_code = fixed_code
                                    except Exception:
                                        pass
                            attempt += 1

                self._emit("step_done", {"step": 3.5, "name": f"Adım 5: Derleme ve Syntax Kontrolü ({query})", "data": {"message": compiler_msg}})

                # ────────────────────────────────────────
                # ADIM 5.3: Payload Enjeksiyonu (Opsiyonel)
                # ────────────────────────────────────────
                if payload_inject and llm:
                    self._emit("step_start", {"step": 3.6, "name": f"Adım 5.3: Payload Enjeksiyonu - {query}"})
                    try:
                        from offsploit.payload_engine import PayloadEngine, PayloadType
                        payload_eng = PayloadEngine(llm)
                        profile = payload_eng.detect_target_profile(service_data)

                        # Payload type ayarla
                        try:
                            profile.payload_type = PayloadType(payload_type)
                        except ValueError:
                            profile.payload_type = PayloadType.REVERSE_TCP

                        payload_result = payload_eng.inject_payload(
                            exploit_code=adapted_code,
                            target_profile=profile,
                            lhost=lhost,
                            lport=lport,
                        )
                        if payload_result.success:
                            adapted_code = payload_result.injected_code
                            compiler_msg += f" | [PAYLOAD:{payload_result.payload_type}]"
                            logger.info("Payload enjeksiyonu başarılı: %s", payload_result.payload_type)
                        else:
                            logger.warning("Payload enjeksiyonu başarısız: %s", payload_result.message)
                    except Exception as e:
                        logger.error("Payload enjeksiyon hatası: %s", e)
                    self._emit("step_done", {"step": 3.6, "name": f"Adım 5.3: Payload Enjeksiyonu - {query}", "data": {"message": compiler_msg}})

                # ────────────────────────────────────────
                # ADIM 5.4: Ghost Mode (Legacy, Swarm yoksa)
                # ────────────────────────────────────────
                if ghost and llm and not swarm:
                    self._emit("step_start", {"step": 3.7, "name": f"Adım 5.4: Ghost Mode (OPSEC Motoru) - {query}"})
                    try:
                        ghost_code = llm.apply_ghost_mode(
                            source_code=adapted_code,
                            model_override=self.config.get("ollama_model")
                        )
                        if ghost_code and not ghost_code.startswith("**HATA**"):
                            adapted_code = ghost_code
                            compiler_msg += " | [GHOST]"
                            logger.info("Ghost Mode OPSEC routines successfully injected.")
                        else:
                            logger.warning("Ghost Mode API returned error or empty response.")
                    except Exception as e:
                        logger.error("Ghost Mode failed: %s", e)
                    self._emit("step_done", {"step": 3.7, "name": f"Adım 5.4: Ghost Mode (OPSEC Motoru) - {query}", "data": {"message": "OPSEC routines injected" if "[GHOST]" in compiler_msg else "Ghost Mode skipped/failed"}})

                # ────────────────────────────────────────
                # ADIM 5.5: Evasion Engine (v1) veya Legacy Obfuscation
                # ────────────────────────────────────────
                if (evasion or obfuscate) and llm:
                    self._emit("step_start", {"step": 3.8, "name": f"Adım 5.5: Evasion / Obfuscation - {query}"})
                    try:
                        if evasion:
                            # v1 Evasion Engine
                            from offsploit.evasion_engine import EvasionEngine
                            evasion_eng = EvasionEngine(
                                llm_client=llm,
                                evasion_level=evasion_level or cfg.get("evasion_level", "advanced"),
                            )

                            # Hedef OS tespit
                            target_os = "linux"
                            for svc in service_data:
                                if "windows" in str(svc.get("name", "")).lower() or "microsoft" in str(svc.get("product", "")).lower():
                                    target_os = "windows"
                                    break

                            evasion_result = evasion_eng.transform(
                                code=adapted_code,
                                target_os=target_os,
                            )

                            if evasion_result.success:
                                adapted_code = evasion_result.transformed_code
                                techniques_str = ",".join(evasion_result.techniques_applied[:3])
                                compiler_msg += f" | [EVASION:{techniques_str}]"
                            else:
                                logger.warning("Evasion başarısız: %s", evasion_result.message)
                        else:
                            # Legacy Obfuscation
                            from offsploit.compiler_agent import CompilerAgent
                            advanced_techniques = [
                                "Sandbox Evasion (Time/CPU check)",
                                "Anti-Debugging (IsDebuggerPresent/ptrace vb.)",
                                "String Encryption (XOR/Base64 vb.)",
                                "Junk Code (Ölü Kod Ekleme)"
                            ]
                            obf_code = llm.obfuscate_code(
                                source_code=adapted_code,
                                model_override=self.config.get("ollama_model"),
                                techniques=advanced_techniques
                            )
                            if obf_code and not obf_code.startswith("**HATA**"):
                                # Re-verify
                                success_compile = True
                                if lang == "Python":
                                    success_compile, _, _ = CompilerAgent.check_python_syntax(obf_code)
                                elif lang in ["C", "C++"]:
                                    success_compile, _, _ = CompilerAgent.compile_and_check(obf_code, language=lang)

                                if success_compile:
                                    adapted_code = obf_code
                                    compiler_msg += " | [OBFUSCATED]"
                                else:
                                    logger.warning("Obfuscated code failed syntax check. Reverting.")
                    except Exception as e:
                        logger.error("Evasion/Obfuscation hatası: %s", e)
                    self._emit("step_done", {"step": 3.8, "name": f"Adım 5.5: Evasion / Obfuscation - {query}", "data": {"message": compiler_msg}})

                # ────────────────────────────────────────
                # ADIM 5.6: Fileless (In-Memory)
                # ────────────────────────────────────────
                if fileless and llm:
                    self._emit("step_start", {"step": 3.9, "name": f"Adım 5.6: Bellek-İçi (Fileless) Sarmalayıcı Üretimi - {query}"})
                    try:
                        fileless_code = llm.generate_fileless_payload(
                            source_code=adapted_code,
                            model_override=self.config.get("ollama_model")
                        )
                        if fileless_code and not fileless_code.startswith("**HATA**"):
                            adapted_code = fileless_code
                            compiler_msg += " | [FILELESS]"
                            logger.info("Fileless payload successfully generated.")
                    except Exception as e:
                        logger.error("Fileless generation failed: %s", e)
                    self._emit("step_done", {"step": 3.9, "name": f"Adım 5.6: Bellek-İçi (Fileless) Sarmalayıcı Üretimi - {query}", "data": {"message": "Fileless wrapper created" if "[FILELESS]" in compiler_msg else "Fileless skipped/failed"}})

                # ────────────────────────────────────────
                # ADIM 6: Kaydet
                # ────────────────────────────────────────
                ext = {".c": ".c", ".cpp": ".c", ".py": ".py", ".rb": ".rb", ".pl": ".pl", ".sh": ".sh"}.get(suffix, ".txt")
                safe_query = "".join([c if c.isalnum() else "_" for c in query])
                output_file = output_dir / f"exploit_{safe_query}{ext}"

                counter = 1
                while output_file.exists():
                    output_file = output_dir / f"exploit_{safe_query}_{counter}{ext}"
                    counter += 1
                output_file.write_text(adapted_code, encoding="utf-8")

                successful_exploits.append({
                    "query": query,
                    "description": match.description,
                    "platform": match.platform,
                    "type": match.exploit_type,
                    "distance": round(match.distance, 4),
                    "file_path": match.file_path,
                    "output_path": str(output_file.resolve()),
                    "compiler_msg": compiler_msg,
                    "adapted_code": adapted_code
                })

            # ════════════════════════════════════════════
            # ADIM 7: Rapor Üretimi
            # ════════════════════════════════════════════
            self._emit("step_start", {"step": 4, "name": "Adım 7: Nihai Rapor Üretimi"})
            from offsploit.reporter import OffSploitReporter
            reporter = OffSploitReporter(target_ip=rhost if rhost else "Bilinmeyen Hedef", output_dir=cfg["output_dir"])
            report_path = reporter.generate_report(lhost=lhost, lport=lport, services=service_data, successful_exploits=successful_exploits)

            if report_path:
                self._emit("step_done", {"step": 4, "name": "Adım 7: Nihai Rapor Üretimi", "data": {"path": report_path}})

            # ════════════════════════════════════════════
            # ADIM 8: State Machine Kaydı (Opsiyonel)
            # ════════════════════════════════════════════
            state_machine_data = None
            if successful_exploits and rhost:
                try:
                    from offsploit.state_machine import AccessLevel, AttackStateMachine, PivotNode
                    sm = AttackStateMachine(
                        rag_engine=rag,
                        llm_client=llm,
                        on_event=self._emit,
                        persist_path=str(output_dir / "state_machine.json") if cfg.get("state_machine_persist") else None,
                    )

                    # Başarılı exploit'leri shell olarak kaydet
                    pivot = PivotNode(
                        ip=rhost,
                        os=services[0].ostype if services and hasattr(services[0], 'ostype') else "",
                        access_level=AccessLevel.USER,
                        shell_type="unknown",
                    )
                    sm.register_shell(pivot)

                    # Sonraki adımı planla
                    next_move = sm.plan_next_move()
                    state_machine_data = {
                        "status": sm.get_status(),
                        "next_move": next_move,
                    }

                    self._emit("state_machine_update", state_machine_data)
                    logger.info("[StateMachine] İlk pivot kaydedildi: %s", rhost)
                except Exception as e:
                    logger.error("State Machine hatası: %s", e)

            # ════════════════════════════════════════════
            # TAMAMLANDI
            # ════════════════════════════════════════════
            self._emit("complete", {
                "success": True,
                "exploits": successful_exploits,
                "report_path": report_path,
                "state_machine": state_machine_data,
            })

        except Exception as exc:
            logger.critical("Pipeline hatasi: %s", exc, exc_info=True)
            self._emit("error", {"message": str(exc)})
            self._emit("complete", {"success": False, "message": str(exc)})

    def _handle_cancel(self):
        self._emit("complete", {"success": False, "message": "Iptal edildi"})
