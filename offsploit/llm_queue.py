#!/usr/bin/env python3
"""
OffSploit - LLM Task Queue (asyncio)
======================================
VRAM sınırlaması (RTX 3060 12GB) nedeniyle LLM çağrılarını
sıralı işleten asyncio.Queue tabanlı kuyruk yöneticisi.

LLM task'ları bu kuyruktan sırayla çekilir ve teker teker işlenir.
Docker build ve statik analiz gibi I/O-bound işlemler ise
asyncio.gather() ile paralel çalıştırılabilir.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("offsploit.llm_queue")


@dataclass
class LLMTask:
    """Kuyrukta bekleyen bir LLM görevi.

    Attributes:
        callable: Çağrılacak senkron fonksiyon.
        args: Fonksiyon argümanları.
        kwargs: Fonksiyon keyword argümanları.
        future: Sonucun yazılacağı asyncio.Future.
        name: Görev adı (loglama için).
        submitted_at: Gönderim zamanı.
    """
    callable: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    future: asyncio.Future = None
    name: str = ""
    submitted_at: float = 0.0


class LLMTaskQueue:
    """Sıralı LLM görev kuyruğu.

    VRAM sınırlaması nedeniyle LLM çağrıları paralel yapılamaz.
    Bu sınıf bir asyncio.Queue kullanarak LLM görevlerini sırayla işler.

    Kullanım:
        queue = LLMTaskQueue()
        await queue.start()

        # Submit ve sonuç bekle
        result = await queue.submit(llm.adapt_exploit, code, lhost, rhost, lport)

        # Bitişte dur
        await queue.stop()
    """

    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: asyncio.Task | None = None
        self._running: bool = False
        self._processed_count: int = 0
        self._processing_times: list[float] = []

    async def start(self):
        """Kuyruk worker'ını başlatır."""
        if self._running:
            logger.warning("LLMTaskQueue zaten çalışıyor.")
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker())
        logger.info("LLMTaskQueue başlatıldı. LLM görevleri sıralı işlenecek.")

    async def stop(self):
        """Kuyruk worker'ını durdurur."""
        self._running = False
        if self._worker_task:
            # Sentinel göndererek worker'ı uyandır
            await self._queue.put(None)
            try:
                await asyncio.wait_for(self._worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._worker_task.cancel()
            self._worker_task = None
        logger.info(
            "LLMTaskQueue durduruldu. Toplam işlenen: %d görev.",
            self._processed_count,
        )

    async def _worker(self):
        """Kuyruktan görevleri sırayla çekip işleyen worker loop."""
        logger.info("LLM Worker başladı — görevler SIRAYLA işlenecek (OOM koruması).")
        while self._running:
            try:
                task = await self._queue.get()

                # Sentinel: None gelirse dur
                if task is None:
                    self._queue.task_done()
                    break

                task_name = task.name or f"LLMTask-{self._processed_count + 1}"
                wait_time = time.monotonic() - task.submitted_at
                logger.info(
                    "[LLM Queue] Görev başlıyor: '%s' (kuyrukta bekleme: %.2fs)",
                    task_name,
                    wait_time,
                )

                start_time = time.monotonic()
                try:
                    # Senkron LLM çağrısını thread'e sararak çalıştır
                    result = await asyncio.to_thread(
                        task.callable, *task.args, **task.kwargs
                    )
                    if task.future and not task.future.done():
                        task.future.set_result(result)

                    elapsed = time.monotonic() - start_time
                    self._processing_times.append(elapsed)
                    logger.info(
                        "[LLM Queue] Görev tamamlandı: '%s' (süre: %.2fs)",
                        task_name,
                        elapsed,
                    )
                except Exception as e:
                    elapsed = time.monotonic() - start_time
                    logger.error(
                        "[LLM Queue] Görev başarısız: '%s' — %s (süre: %.2fs)",
                        task_name,
                        e,
                        elapsed,
                    )
                    if task.future and not task.future.done():
                        task.future.set_exception(e)
                finally:
                    self._processed_count += 1
                    self._queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("[LLM Queue] Worker hatası: %s", e)

    async def submit(
        self,
        callable: Callable,
        *args,
        name: str = "",
        **kwargs,
    ) -> Any:
        """Bir LLM görevini kuyruğa ekler ve sonucunu bekler.

        Args:
            callable: Çağrılacak senkron LLM fonksiyonu.
            *args: Fonksiyon argümanları.
            name: Görev adı (loglama için).
            **kwargs: Fonksiyon keyword argümanları.

        Returns:
            LLM fonksiyonunun döndürdüğü sonuç.
        """
        loop = asyncio.get_event_loop()
        future = loop.create_future()

        task = LLMTask(
            callable=callable,
            args=args,
            kwargs=kwargs,
            future=future,
            name=name,
            submitted_at=time.monotonic(),
        )

        await self._queue.put(task)
        logger.debug(
            "[LLM Queue] Görev kuyruğa eklendi: '%s' (kuyruk boyutu: %d)",
            name,
            self._queue.qsize(),
        )

        return await future

    @property
    def pending_count(self) -> int:
        """Kuyrukta bekleyen görev sayısı."""
        return self._queue.qsize()

    @property
    def processed_count(self) -> int:
        """Toplam işlenen görev sayısı."""
        return self._processed_count

    @property
    def is_running(self) -> bool:
        """Worker çalışıyor mu."""
        return self._running

    def get_stats(self) -> dict[str, Any]:
        """Kuyruk istatistiklerini döndürür."""
        avg_time = (
            sum(self._processing_times) / len(self._processing_times)
            if self._processing_times
            else 0
        )
        return {
            "processed_count": self._processed_count,
            "pending_count": self._queue.qsize(),
            "avg_processing_time": round(avg_time, 3),
            "is_running": self._running,
        }
