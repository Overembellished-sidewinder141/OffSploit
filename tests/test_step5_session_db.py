#!/usr/bin/env python3
"""
OffSploit - Adım 5 Testleri: SQLite Session DB
=================================================
"""

import os
import tempfile

import pytest


@pytest.fixture
def session_db():
    """Geçici SQLite DB ile SessionManager oluşturur."""
    from offsploit.session_db import SessionManager

    # Geçici dosya (Windows'ta auto-delete sorunlarını önlemek için)
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    manager = SessionManager(db_path=path)
    yield manager

    # Temizlik
    manager.close()
    try:
        os.unlink(path)
    except OSError:
        pass
    # WAL dosyalarını da temizle
    for ext in ("-wal", "-shm"):
        try:
            os.unlink(path + ext)
        except OSError:
            pass


# ─────────────────────────────────────────────
# Test 1: Session oluşturma ve alma
# ─────────────────────────────────────────────

def test_create_and_get_session(session_db):
    """Session oluştur ve get_session ile doğrula."""
    session_id = session_db.create_session(
        target_ip="192.168.1.100",
        config={"ollama_model": "test-model", "top_k": 5},
    )

    assert session_id is not None
    assert len(session_id) == 8

    session = session_db.get_session(session_id)
    assert session is not None
    assert session["session_id"] == session_id
    assert session["target_ip"] == "192.168.1.100"
    assert session["status"] == "running"
    assert session["config_snapshot"]["ollama_model"] == "test-model"
    assert session["started_at"] is not None
    assert session["finished_at"] is None


# ─────────────────────────────────────────────
# Test 2: 5 adım loglama
# ─────────────────────────────────────────────

def test_log_five_steps(session_db):
    """5 adım logla ve doğrula."""
    session_id = session_db.create_session(target_ip="10.0.0.1")

    step_types = [
        ("Nmap Parse", "nmap_parse"),
        ("RAG Search", "rag_search"),
        ("LLM Adapt", "llm_adapt"),
        ("Docker Compile", "docker_compile"),
        ("Report Generate", "report"),
    ]

    step_ids = []
    for step_name, step_type in step_types:
        step_id = session_db.log_step(
            session_id=session_id,
            step_name=step_name,
            step_type=step_type,
            status="running",
            input_summary=f"Input for {step_name}",
        )
        step_ids.append(step_id)

    # Toplam step sayısı
    count = session_db.get_step_count(session_id)
    assert count == 5

    # Tüm stepleri getir
    steps = session_db.get_steps(session_id)
    assert len(steps) == 5
    assert steps[0]["step_name"] == "Nmap Parse"
    assert steps[0]["step_type"] == "nmap_parse"
    assert steps[4]["step_name"] == "Report Generate"
    assert steps[4]["step_type"] == "report"


# ─────────────────────────────────────────────
# Test 3: Tam oturum simülasyonu
# ─────────────────────────────────────────────

def test_full_session_lifecycle(session_db):
    """Tam bir pipeline oturum simülasyonu."""
    # Session oluştur
    session_id = session_db.create_session(
        target_ip="172.16.0.5",
        config={"ollama_model": "qwen2.5-coder:14b"},
    )

    # Adımları sırayla logla
    step1_id = session_db.log_step(
        session_id, "Nmap Ayrıştırma", "nmap_parse",
        input_summary="nmap_result.xml",
    )
    session_db.update_step(step1_id, status="success", output_summary="3 hedef bulundu")

    step2_id = session_db.log_step(
        session_id, "RAG Arama", "rag_search",
        input_summary="vsftpd 2.3.4",
    )
    session_db.update_step(step2_id, status="success", output_summary="2 exploit bulundu")

    step3_id = session_db.log_step(
        session_id, "LLM Uyarlama", "llm_adapt",
        input_summary="Exploit #1234",
    )
    session_db.update_step(
        step3_id,
        status="success",
        output_summary="Kod uyarlandı (1024 byte)",
        metadata={"exploit_id": "1234", "code_length": 1024},
    )

    step4_id = session_db.log_step(
        session_id, "Docker Derleme", "docker_compile",
        input_summary="gcc compilation",
    )
    session_db.update_step(
        step4_id,
        status="failed",
        error_message="Derleme hatası: undefined reference to 'main'",
    )

    # Session'ı bitir
    session_db.finish_session(session_id, status="completed")

    # Doğrula
    session = session_db.get_session(session_id)
    assert session["status"] == "completed"
    assert session["finished_at"] is not None
    assert session["target_ip"] == "172.16.0.5"

    steps = session_db.get_steps(session_id)
    assert len(steps) == 4

    # Başarılı adım kontrolü
    assert steps[0]["status"] == "success"
    assert steps[0]["output_summary"] == "3 hedef bulundu"

    # Hatalı adım kontrolü
    assert steps[3]["status"] == "failed"
    assert "undefined reference" in steps[3]["error_message"]

    # Metadata kontrolü
    assert steps[2]["metadata"]["exploit_id"] == "1234"
    assert steps[2]["metadata"]["code_length"] == 1024

    # finished_at kontrolü (success/failed adımlarında dolu olmalı)
    assert steps[0]["finished_at"] is not None
    assert steps[3]["finished_at"] is not None


# ─────────────────────────────────────────────
# Test 4: finish_session status kontrolü
# ─────────────────────────────────────────────

def test_finish_session_sets_status(session_db):
    """finish_session() sonrası status doğru olmalı."""
    sid = session_db.create_session(target_ip="10.0.0.1")

    # Varsayılan: running
    session = session_db.get_session(sid)
    assert session["status"] == "running"

    # Tamamla
    session_db.finish_session(sid, status="completed")
    session = session_db.get_session(sid)
    assert session["status"] == "completed"
    assert session["finished_at"] is not None


# ─────────────────────────────────────────────
# Test 5: finish_session — failed status
# ─────────────────────────────────────────────

def test_finish_session_failed(session_db):
    """failed status ile session sonlandırma."""
    sid = session_db.create_session(target_ip="10.0.0.2")
    session_db.finish_session(sid, status="failed")

    session = session_db.get_session(sid)
    assert session["status"] == "failed"


# ─────────────────────────────────────────────
# Test 6: get_all_sessions sıralama ve limit
# ─────────────────────────────────────────────

def test_get_all_sessions(session_db):
    """Birden fazla oturum oluştur, listele."""
    ids = []
    for i in range(5):
        sid = session_db.create_session(target_ip=f"10.0.0.{i}")
        ids.append(sid)

    all_sessions = session_db.get_all_sessions(limit=3)
    assert len(all_sessions) == 3

    all_sessions_full = session_db.get_all_sessions(limit=50)
    assert len(all_sessions_full) == 5


# ─────────────────────────────────────────────
# Test 7: Olmayan session
# ─────────────────────────────────────────────

def test_get_nonexistent_session(session_db):
    """Olmayan session_id None döndürmeli."""
    result = session_db.get_session("nonexistent")
    assert result is None


# ─────────────────────────────────────────────
# Test 8: Boş config ile session
# ─────────────────────────────────────────────

def test_session_without_config(session_db):
    """Config olmadan session oluşturulabilmeli."""
    sid = session_db.create_session(target_ip="10.0.0.1")
    session = session_db.get_session(sid)
    assert session["config_snapshot"] is None


# ─────────────────────────────────────────────
# Test 9: update_step metadata
# ─────────────────────────────────────────────

def test_update_step_metadata(session_db):
    """update_step ile metadata güncellenebilmeli."""
    sid = session_db.create_session(target_ip="10.0.0.1")
    step_id = session_db.log_step(sid, "Test Step", "test")

    session_db.update_step(
        step_id,
        metadata={"key": "value", "count": 42},
    )

    steps = session_db.get_steps(sid)
    assert len(steps) == 1
    assert steps[0]["metadata"]["key"] == "value"
    assert steps[0]["metadata"]["count"] == 42


# ─────────────────────────────────────────────
# Test 10: Thread safety
# ─────────────────────────────────────────────

def test_thread_safety(session_db):
    """Birden fazla thread'den eşzamanlı yazma hataya yol açmamalı."""
    import threading

    sid = session_db.create_session(target_ip="10.0.0.1")
    errors = []

    def log_from_thread(thread_id: int):
        try:
            for i in range(10):
                session_db.log_step(
                    sid,
                    f"Thread-{thread_id}-Step-{i}",
                    "test",
                    status="success",
                )
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=log_from_thread, args=(t,))
        for t in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Thread hatası: {errors}"

    # 4 thread * 10 step = 40 adım
    count = session_db.get_step_count(sid)
    assert count == 40
