#!/usr/bin/env python3
"""
OffSploit - SQLite Session Database
=====================================
Pipeline oturumlarını ve adım loglarını SQLite veritabanına
kaydeden modül. Thread-safe, hafif ve harici bağımlılık gerektirmez.
"""

import contextlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("offsploit.session_db")


class SessionManager:
    """SQLite tabanlı oturum ve adım loglama yöneticisi.

    Tablo yapısı:
        - sessions: Pipeline oturum bilgileri
        - session_steps: Her oturumdaki adım logları

    Thread-safe: sqlite3.connect(check_same_thread=False) + threading.Lock()
    """

    def __init__(self, db_path: str = "offsploit_sessions.db"):
        """SessionManager başlatır.

        Args:
            db_path: SQLite veritabanı dosya yolu.
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Veritabanı bağlantısını döndürür (lazy init)."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            # WAL modu — okuma ve yazma eşzamanlılığı
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self):
        """Tabloları oluşturur (idempotent)."""
        with self._lock:
            conn = self._get_conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    target_ip TEXT,
                    status TEXT DEFAULT 'running',
                    config_snapshot TEXT
                );

                CREATE TABLE IF NOT EXISTS session_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(session_id),
                    step_name TEXT NOT NULL,
                    step_type TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    status TEXT DEFAULT 'pending',
                    input_summary TEXT,
                    output_summary TEXT,
                    error_message TEXT,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_steps_session
                    ON session_steps(session_id);

                CREATE INDEX IF NOT EXISTS idx_sessions_status
                    ON sessions(status);
            """)
            conn.commit()
            logger.info("Session DB başlatıldı: %s", self.db_path)

    # ── Session CRUD ──

    def create_session(
        self,
        target_ip: str = "",
        config: dict[str, Any] | None = None,
    ) -> str:
        """Yeni bir pipeline oturumu oluşturur.

        Args:
            target_ip: Hedef IP adresi.
            config: Pipeline yapılandırma snapshot'ı.

        Returns:
            Benzersiz session_id.
        """
        session_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        config_json = json.dumps(config, ensure_ascii=False) if config else None

        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """INSERT INTO sessions (session_id, started_at, target_ip, status, config_snapshot)
                   VALUES (?, ?, ?, 'running', ?)""",
                (session_id, now, target_ip, config_json),
            )
            conn.commit()

        logger.info("Yeni oturum oluşturuldu: %s (hedef: %s)", session_id, target_ip)
        return session_id

    def finish_session(self, session_id: str, status: str = "completed"):
        """Bir oturumu sonlandırır.

        Args:
            session_id: Oturum ID'si.
            status: Son durum ('completed', 'failed', 'cancelled').
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """UPDATE sessions SET finished_at = ?, status = ?
                   WHERE session_id = ?""",
                (now, status, session_id),
            )
            conn.commit()

        logger.info("Oturum sonlandı: %s → %s", session_id, status)

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Oturum bilgilerini döndürür.

        Args:
            session_id: Oturum ID'si.

        Returns:
            Oturum dict'i veya None.
        """
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()

        if not row:
            return None

        result = dict(row)
        if result.get("config_snapshot"):
            with contextlib.suppress(json.JSONDecodeError):
                result["config_snapshot"] = json.loads(result["config_snapshot"])
        return result

    def get_all_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Tüm oturumları listeler (en yeniden eskiye).

        Args:
            limit: Döndürülecek maksimum oturum sayısı.

        Returns:
            Oturum dict listesi.
        """
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            if d.get("config_snapshot"):
                with contextlib.suppress(json.JSONDecodeError):
                    d["config_snapshot"] = json.loads(d["config_snapshot"])
            results.append(d)
        return results

    # ── Step CRUD ──

    def log_step(
        self,
        session_id: str,
        step_name: str,
        step_type: str,
        status: str = "running",
        input_summary: str = "",
        output_summary: str = "",
        error_message: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Bir pipeline adımını loglar.

        Args:
            session_id: Oturum ID'si.
            step_name: Adım adı (insana okunur).
            step_type: Adım tipi ('nmap_parse', 'rag_search', vb.).
            status: Durum ('pending', 'running', 'success', 'failed', 'skipped').
            input_summary: Giriş özeti.
            output_summary: Çıkış özeti.
            error_message: Hata mesajı (varsa).
            metadata: Ekstra JSON metadata.

        Returns:
            Oluşturulan step ID'si.
        """
        now = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(metadata, ensure_ascii=False) if metadata else None

        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO session_steps
                   (session_id, step_name, step_type, started_at, status,
                    input_summary, output_summary, error_message, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, step_name, step_type, now, status,
                 input_summary, output_summary, error_message, metadata_json),
            )
            conn.commit()
            step_id = cursor.lastrowid

        logger.debug("Step logged: %s/%s → %s (id=%d)", session_id, step_name, status, step_id)
        return step_id

    def update_step(
        self,
        step_id: int,
        status: str | None = None,
        output_summary: str | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """Mevcut bir adımı günceller.

        Args:
            step_id: Adım ID'si.
            status: Yeni durum (opsiyonel).
            output_summary: Yeni çıkış özeti (opsiyonel).
            error_message: Yeni hata mesajı (opsiyonel).
            metadata: Yeni metadata (opsiyonel).
        """
        updates: list[str] = []
        values: list[Any] = []

        if status is not None:
            updates.append("status = ?")
            values.append(status)
        if output_summary is not None:
            updates.append("output_summary = ?")
            values.append(output_summary)
        if error_message is not None:
            updates.append("error_message = ?")
            values.append(error_message)
        if metadata is not None:
            updates.append("metadata = ?")
            values.append(json.dumps(metadata, ensure_ascii=False))

        # finished_at otomatik ekle
        if status in ("success", "failed", "skipped"):
            updates.append("finished_at = ?")
            values.append(datetime.now(timezone.utc).isoformat())

        if not updates:
            return

        values.append(step_id)
        sql = f"UPDATE session_steps SET {', '.join(updates)} WHERE id = ?"

        with self._lock:
            conn = self._get_conn()
            conn.execute(sql, values)
            conn.commit()

    def get_steps(self, session_id: str) -> list[dict[str, Any]]:
        """Bir oturumun tüm adımlarını döndürür.

        Args:
            session_id: Oturum ID'si.

        Returns:
            Adım dict listesi (sıralı).
        """
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(
                "SELECT * FROM session_steps WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            if d.get("metadata"):
                with contextlib.suppress(json.JSONDecodeError):
                    d["metadata"] = json.loads(d["metadata"])
            results.append(d)
        return results

    def get_step_count(self, session_id: str) -> int:
        """Bir oturumdaki adım sayısını döndürür."""
        with self._lock:
            conn = self._get_conn()
            result = conn.execute(
                "SELECT COUNT(*) FROM session_steps WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return result[0] if result else 0

    # ── Cleanup ──

    def close(self):
        """Veritabanı bağlantısını kapatır."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
                logger.info("Session DB bağlantısı kapatıldı.")

    def __del__(self):
        self.close()
