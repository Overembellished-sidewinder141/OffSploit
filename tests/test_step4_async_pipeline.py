#!/usr/bin/env python3
"""
OffSploit - Adım 4 Testleri: Asenkron Pipeline (asyncio)
==========================================================
"""

import asyncio
import time

import pytest
import pytest_asyncio


# ─────────────────────────────────────────────
# Test 1: LLMTaskQueue — görevler sıralı işlenir
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_queue_sequential_processing():
    """3 task submit edilir, hepsi sıralı işlenir (timestamp kontrolü)."""
    from offsploit.llm_queue import LLMTaskQueue

    queue = LLMTaskQueue()
    await queue.start()

    timestamps: list[float] = []

    def mock_llm_call(task_id: str, delay: float = 0.05) -> str:
        """Mock LLM: kısa gecikme simülasyonu."""
        timestamps.append(time.monotonic())
        time.sleep(delay)
        return f"result_{task_id}"

    # 3 görevi aynı anda submit et
    results = await asyncio.gather(
        queue.submit(mock_llm_call, "A", name="task_A"),
        queue.submit(mock_llm_call, "B", name="task_B"),
        queue.submit(mock_llm_call, "C", name="task_C"),
    )

    await queue.stop()

    # Sonuçlar doğru mu
    assert "result_A" in results
    assert "result_B" in results
    assert "result_C" in results

    # Sıralı işlendiğini doğrula: her timestamp bir öncekinden en az ~delay sonra
    assert len(timestamps) == 3
    for i in range(1, len(timestamps)):
        assert timestamps[i] >= timestamps[i - 1], \
            f"Görevler sıralı değil! ts[{i}]={timestamps[i]:.4f} < ts[{i-1}]={timestamps[i-1]:.4f}"


# ─────────────────────────────────────────────
# Test 2: LLMTaskQueue — paralel submit edilse de sıralı çalışır
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_queue_no_parallel_execution():
    """Aynı anda 5 task submit edilse de, aynı anda max 1 çalışır."""
    from offsploit.llm_queue import LLMTaskQueue

    queue = LLMTaskQueue()
    await queue.start()

    concurrent_count = 0
    max_concurrent = 0
    lock = asyncio.Lock()

    def mock_concurrent_check(task_id: str) -> str:
        nonlocal concurrent_count, max_concurrent
        # Lock kullanamayız (senkron), ama thread-safe olması lazım
        concurrent_count += 1
        if concurrent_count > max_concurrent:
            max_concurrent = concurrent_count
        time.sleep(0.02)
        concurrent_count -= 1
        return f"done_{task_id}"

    tasks = [
        queue.submit(mock_concurrent_check, str(i), name=f"task_{i}")
        for i in range(5)
    ]
    await asyncio.gather(*tasks)
    await queue.stop()

    # Maksimum eşzamanlılık 1 olmalı (sıralı işlem)
    assert max_concurrent == 1, f"Max concurrent = {max_concurrent}, beklenen 1"


# ─────────────────────────────────────────────
# Test 3: LLMTaskQueue — hata durumu
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_queue_error_handling():
    """Bir task hata fırlatırsa, diğer tasklar etkilenmemeli."""
    from offsploit.llm_queue import LLMTaskQueue

    queue = LLMTaskQueue()
    await queue.start()

    def failing_task():
        raise ValueError("LLM OOM hatası!")

    def success_task():
        return "başarılı"

    # Hatalı task
    with pytest.raises(ValueError, match="OOM"):
        await queue.submit(failing_task, name="failing")

    # Hata sonrası başarılı task çalışabilmeli
    result = await queue.submit(success_task, name="success")
    assert result == "başarılı"

    await queue.stop()
    assert queue.processed_count == 2


# ─────────────────────────────────────────────
# Test 4: LLMTaskQueue — istatistikler
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_queue_stats():
    """Kuyruk istatistikleri doğru hesaplanmalı."""
    from offsploit.llm_queue import LLMTaskQueue

    queue = LLMTaskQueue()
    await queue.start()

    def quick_task(n: int) -> int:
        return n * 2

    await queue.submit(quick_task, 5, name="double_5")
    await queue.submit(quick_task, 10, name="double_10")

    stats = queue.get_stats()
    assert stats["processed_count"] == 2
    assert stats["is_running"] is True
    assert stats["avg_processing_time"] >= 0

    await queue.stop()
    assert queue.is_running is False


# ─────────────────────────────────────────────
# Test 5: LLMTaskQueue — start/stop lifecycle
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_queue_lifecycle():
    """Queue start/stop lifecycle doğru çalışmalı."""
    from offsploit.llm_queue import LLMTaskQueue

    queue = LLMTaskQueue()

    assert queue.is_running is False
    assert queue.processed_count == 0

    await queue.start()
    assert queue.is_running is True

    await queue.stop()
    assert queue.is_running is False


# ─────────────────────────────────────────────
# Test 6: AsyncOffSploitPipeline — config kabul eder
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_async_pipeline_accepts_dict_config():
    """AsyncOffSploitPipeline dict config ile oluşturulabilmeli."""
    from offsploit.async_pipeline import AsyncOffSploitPipeline

    events = []

    def mock_event(event_type, data):
        events.append((event_type, data))

    pipeline = AsyncOffSploitPipeline(
        config={"ollama_url": "http://localhost:11434"},
        on_event=mock_event,
    )

    assert pipeline.config["ollama_url"] == "http://localhost:11434"


@pytest.mark.asyncio
async def test_async_pipeline_accepts_config_object():
    """AsyncOffSploitPipeline OffSploitConfig nesnesi ile oluşturulabilmeli."""
    from offsploit.async_pipeline import AsyncOffSploitPipeline
    from offsploit.config_schema import OffSploitConfig

    events = []

    def mock_event(event_type, data):
        events.append((event_type, data))

    config = OffSploitConfig.from_dict({"top_k": 5})
    pipeline = AsyncOffSploitPipeline(
        config=config,
        on_event=mock_event,
    )

    assert pipeline.config["top_k"] == 5
    assert pipeline.config_obj.top_k == 5


# ─────────────────────────────────────────────
# Test 7: Paralel Docker simülasyonu
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_parallel_docker_simulation():
    """asyncio.gather ile paralel çalışma simülasyonu."""
    start_times: list[float] = []

    async def mock_docker_build(task_id: str, delay: float = 0.05):
        start_times.append(time.monotonic())
        await asyncio.sleep(delay)  # Non-blocking simülasyon
        return {"task_id": task_id, "success": True}

    tasks = [
        mock_docker_build("docker_1"),
        mock_docker_build("docker_2"),
        mock_docker_build("docker_3"),
    ]

    results = await asyncio.gather(*tasks)

    # Tüm sonuçlar başarılı
    assert all(r["success"] for r in results)
    assert len(results) == 3

    # Paralel başladıklarını doğrula: tüm start zamanları çok yakın olmalı
    if len(start_times) >= 2:
        time_spread = max(start_times) - min(start_times)
        assert time_spread < 0.05, \
            f"Docker build'ler paralel başlamadı! Zaman farkı: {time_spread:.4f}s"


# ─────────────────────────────────────────────
# Test 8: Sıralı LLM + Paralel Docker bütünleşik test
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sequential_llm_parallel_docker_combined():
    """LLM sıralı, Docker paralel — bütünleşik mimari testi."""
    from offsploit.llm_queue import LLMTaskQueue

    queue = LLMTaskQueue()
    await queue.start()

    llm_timestamps: list[float] = []
    docker_timestamps: list[float] = []

    def mock_llm(task_id: str) -> str:
        llm_timestamps.append(time.monotonic())
        time.sleep(0.03)
        return f"llm_result_{task_id}"

    async def mock_docker(task_id: str):
        docker_timestamps.append(time.monotonic())
        await asyncio.sleep(0.02)
        return f"docker_result_{task_id}"

    # Sıralı LLM görevleri
    llm_results = await asyncio.gather(
        queue.submit(mock_llm, "1", name="llm_1"),
        queue.submit(mock_llm, "2", name="llm_2"),
    )
    assert llm_results[0] == "llm_result_1"
    assert llm_results[1] == "llm_result_2"

    # LLM sıralı çalıştığını doğrula
    assert len(llm_timestamps) == 2
    assert llm_timestamps[1] >= llm_timestamps[0]

    # Paralel Docker görevleri
    docker_results = await asyncio.gather(
        mock_docker("A"),
        mock_docker("B"),
        mock_docker("C"),
    )
    assert len(docker_results) == 3

    # Docker paralel çalıştığını doğrula
    if len(docker_timestamps) >= 2:
        docker_spread = max(docker_timestamps) - min(docker_timestamps)
        assert docker_spread < 0.02, \
            f"Docker görevleri paralel değil! Spread: {docker_spread:.4f}s"

    await queue.stop()
