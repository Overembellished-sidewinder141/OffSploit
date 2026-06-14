#!/usr/bin/env python3
"""
OffSploit - Asenkron Pipeline (asyncio)
========================================
core_pipeline.py'nin asenkron versiyonu.

Mimari kararlar:
    - LLM çağrıları: asyncio.Queue ile sıralı (OOM koruması)
    - Docker build/statik analiz: asyncio.gather() ile paralel
    - Event emitter: asenkron callback desteği
"""

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

from offsploit.config_schema import OffSploitConfig
from offsploit.llm_client import LLMClient
from offsploit.llm_queue import LLMTaskQueue
from offsploit.nmap_parser import NmapParser
from offsploit.rag_engine import OffSploitRAG

logger = logging.getLogger("offsploit.async_pipeline")


class AsyncOffSploitPipeline:
    """Asenkron saldırı pipeline'ı.

    LLM görevleri sıralı kuyrukla, Docker ve I/O işlemleri
    paralel çalıştırılarak OOM riski ortadan kaldırılır.

    Args:
        config: OffSploitConfig veya dict.
        on_event: Durum bildirim callback'i (senkron veya asenkron).
        cancel_check: İptal kontrolü callback'i.
    """

    def __init__(
        self,
        config: OffSploitConfig | dict[str, Any],
        on_event: Callable[[str, dict], None],
        cancel_check: Callable[[], bool] | None = None,
    ):
        # Config normalizasyonu
        if isinstance(config, OffSploitConfig):
            self.config_obj = config
            self.config = config.to_dict()
        elif isinstance(config, dict):
            self.config_obj = OffSploitConfig.from_dict(config)
            self.config = self.config_obj.to_dict()
        else:
            self.config = dict(config)
            self.config_obj = OffSploitConfig.from_dict(self.config)

        self.on_event = on_event
        self.cancel_check = cancel_check or (lambda: False)

        # LLM kuyruk yöneticisi
        self._llm_queue = LLMTaskQueue()

        # State
        self._session_id: str = ""
        self._start_time: float = 0.0
        self._operation_history: list[dict] = []

    # ── Event Emitter ──

    async def _emit(self, event_type: str, data: dict | None = None):
        """Asenkron event emitter."""
        payload = data or {}
        payload.setdefault("session_id", self._session_id)
        payload.setdefault("timestamp", time.time())

        if asyncio.iscoroutinefunction(self.on_event):
            await self.on_event(event_type, payload)
        else:
            self.on_event(event_type, payload)

    # ── Pipeline Adımları ──

    async def _step_parse_nmap(self, nmap_xml: str) -> list[dict]:
        """Adım 1: Nmap XML parse (I/O-bound → thread'e sar)."""
        await self._emit("step_start", {"step": "nmap_parse", "message": "Nmap XML ayrıştırılıyor..."})

        targets = await asyncio.to_thread(NmapParser.parse_xml, nmap_xml)

        await self._emit("step_complete", {
            "step": "nmap_parse",
            "message": f"{len(targets)} hedef bulundu.",
            "target_count": len(targets),
        })
        return targets

    async def _step_rag_search(self, query: str, where: dict | None = None) -> list:
        """Adım 2: RAG araması (I/O-bound → thread'e sar)."""
        await self._emit("step_start", {"step": "rag_search", "message": f"RAG araması: '{query}'"})

        rag = OffSploitRAG(
            chromadb_path=self.config.get("chromadb_path", "./offsploit_chromadb"),
            collection_name=self.config.get("collection_name", "offsploit_db"),
            ollama_url=self.config.get("ollama_url", "http://localhost:11434"),
            embedding_model=self.config.get("embedding_model", "mxbai-embed-large"),
            embedding_provider=self.config.get("embedding_provider", "ollama"),
            top_k=self.config.get("top_k", 2),
        )

        results = await asyncio.to_thread(rag.search, query, None, None, where)

        await self._emit("step_complete", {
            "step": "rag_search",
            "message": f"{len(results)} exploit bulundu.",
            "result_count": len(results),
        })
        return results

    async def _step_llm_adapt(self, exploit_code: str, lhost: str, rhost: str, lport: str) -> str:
        """Adım 3: LLM exploit uyarlama (KUYRUKTAN sıralı)."""
        await self._emit("step_start", {"step": "llm_adapt", "message": "LLM exploit uyarlama kuyruğa alındı..."})

        llm = LLMClient(
            provider_name=self.config.get("llm_provider", "ollama"),
            model=self.config.get("ollama_model", "qwen2.5-coder:14b"),
            ollama_url=self.config.get("ollama_url", "http://localhost:11434"),
            timeout=self.config.get("ollama_timeout", 300),
        )

        # LLM kuyruğundan sıralı çalıştır
        adapted_code = await self._llm_queue.submit(
            llm.adapt_exploit,
            exploit_code,
            lhost,
            rhost,
            lport,
            name="exploit_adapt",
        )

        await self._emit("step_complete", {
            "step": "llm_adapt",
            "message": "Exploit uyarlandı.",
            "code_length": len(adapted_code),
        })
        return adapted_code

    async def _step_docker_compile(self, source_code: str, language: str) -> dict:
        """Adım 4: Docker sandbox derleme (paralel çalışabilir)."""
        await self._emit("step_start", {"step": "docker_compile", "message": f"Docker sandbox derleme: {language}"})

        try:
            from offsploit.docker_sandbox import DockerSandbox

            sandbox = DockerSandbox(
                memory_limit=self.config.get("docker_memory_limit", "256m"),
                cpu_limit=self.config.get("docker_cpu_limit", 0.5),
                timeout=self.config.get("docker_timeout", 30),
            )

            result = await asyncio.to_thread(
                sandbox.compile_in_sandbox, source_code, language
            )

            result_dict = {
                "success": result.success,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except ImportError:
            result_dict = {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": "Docker SDK yüklü değil.",
            }

        await self._emit("step_complete", {
            "step": "docker_compile",
            "message": f"Derleme {'başarılı' if result_dict['success'] else 'başarısız'}.",
            "result": result_dict,
        })
        return result_dict

    # ── Paralel İşlemler ──

    async def _parallel_docker_and_analysis(
        self,
        exploits: list[dict],
    ) -> list[dict]:
        """Docker build ve statik analiz paralel çalıştırılır.

        Args:
            exploits: Her biri {'code': str, 'language': str} içeren exploit listesi.

        Returns:
            Her exploit için derleme sonucu.
        """
        if not exploits:
            return []

        tasks = [
            self._step_docker_compile(e["code"], e["language"])
            for e in exploits
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed = []
        for _i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append({
                    "success": False,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": str(result),
                })
            else:
                processed.append(result)

        return processed

    # ── Ana Pipeline ──

    async def run(
        self,
        nmap_xml: str | None = None,
        targets: list[dict] | None = None,
        lhost: str = "0.0.0.0",
        lport: str = "4444",
    ) -> dict[str, Any]:
        """Ana asenkron pipeline'ı çalıştırır.

        Args:
            nmap_xml: Nmap XML dosya yolu (opsiyonel).
            targets: Önceden parse edilmiş hedefler (opsiyonel).
            lhost: Dinleme IP adresi.
            lport: Dinleme portu.

        Returns:
            Pipeline sonuç raporu.
        """
        self._session_id = str(uuid.uuid4())[:8]
        self._start_time = time.monotonic()

        await self._emit("pipeline_start", {
            "message": "Asenkron pipeline başlatıldı.",
            "lhost": lhost,
            "lport": lport,
        })

        # LLM kuyruk başlat
        await self._llm_queue.start()

        try:
            # Adım 1: Hedef listesi
            if nmap_xml and not targets:
                targets = await self._step_parse_nmap(nmap_xml)
            elif not targets:
                targets = []

            if not targets:
                await self._emit("pipeline_error", {"message": "Hedef bulunamadı."})
                return {"success": False, "error": "No targets"}

            # Adım 2-3: Her hedef için RAG + LLM uyarlama (sıralı)
            all_results: list[dict] = []
            for target in targets:
                if self.cancel_check():
                    await self._emit("pipeline_cancelled", {"message": "Pipeline iptal edildi."})
                    break

                rhost = target.get("ip", "")
                services = target.get("services", [])

                for service in services:
                    query = f"{service.get('product', '')} {service.get('version', '')}".strip()
                    if not query:
                        continue

                    # RAG araması
                    rag_results = await self._step_rag_search(query)

                    # Her exploit için LLM uyarlama (sıralı kuyruktan)
                    for match in rag_results:
                        adapted_code = await self._step_llm_adapt(
                            match.source_code, lhost, rhost, lport
                        )
                        all_results.append({
                            "target": rhost,
                            "service": query,
                            "exploit_id": match.exploit_id,
                            "adapted_code": adapted_code,
                        })

            elapsed = time.monotonic() - self._start_time

            await self._emit("pipeline_complete", {
                "message": f"Pipeline tamamlandı. {len(all_results)} exploit uyarlandı.",
                "total_exploits": len(all_results),
                "elapsed_seconds": round(elapsed, 2),
                "llm_stats": self._llm_queue.get_stats(),
            })

            return {
                "success": True,
                "session_id": self._session_id,
                "results": all_results,
                "elapsed": elapsed,
                "llm_stats": self._llm_queue.get_stats(),
            }

        except Exception as e:
            logger.error("Pipeline hatası: %s", e, exc_info=True)
            await self._emit("pipeline_error", {
                "message": f"Pipeline hatası: {e}",
            })
            return {"success": False, "error": str(e)}

        finally:
            await self._llm_queue.stop()
