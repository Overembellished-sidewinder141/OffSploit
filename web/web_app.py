#!/usr/bin/env python3
"""
OffSploit - Web Application (Flask + Socket.IO)
=================================================
Tum OffSploit modullerini web arayuzu uzerinden yoneten
Flask + Socket.IO tabanli sunucu.

Kullanim:
    python web_app.py
    python web_app.py --port 8080
"""

import json
import logging
import os
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

sys.path.insert(0, str(Path(__file__).parent.parent))

import contextlib

from offsploit.chromadb_ingest import Ingestor
from offsploit.async_pipeline import AsyncOffSploitPipeline
from offsploit.llm_client import LLMClient
from offsploit.rag_engine import OffSploitRAG
from offsploit.session_db import SessionManager

logger = logging.getLogger("offsploit.web")

# Default Configuration

DEFAULT_CONFIG: dict[str, Any] = {
    "ollama_url": "http://localhost:11434",
    "ollama_model": "qwen2.5-coder:14b",
    "ollama_timeout": 300,
    "llm_provider": "ollama",
    "api_key": "",
    "chromadb_path": "./offsploit_chromadb",
    "collection_name": "offsploit_db",
    "exploitdb_root": "exploitdb",
    "csv_path": "exploitdb/files_exploits.csv",
    "top_k": 2,
    "output_dir": "./output",
    # v1.0 Defaults
    "embedding_provider": "ollama",
    "embedding_model": "nomic-embed-text",
    "use_docker_sandbox": True,
    "docker_memory_limit": "256m",
    "docker_cpu_limit": 0.5,
    "docker_timeout": 30,
    "use_swarm": True,
    "swarm_max_rounds": 3,
    "opsec_sensitivity": "moderate",
    "evasion_level": "advanced",
    "state_machine_persist": False,
}


# Config Manager

class ConfigManager:
    """JSON tabanli kalici ayar yoneticisi (Pydantic doğrulamalı)."""

    def __init__(self, config_path: str = "config.json") -> None:
        root_dir = Path(__file__).parent.parent
        self.config_path: Path = root_dir / config_path
        self.config: dict[str, Any] = {}
        self._validated: bool = False
        self.load()

    def load(self) -> None:
        if self.config_path.exists():
            try:
                raw = json.loads(
                    self.config_path.read_text(encoding="utf-8")
                )
                # Pydantic ile doğrula
                from offsploit.config_schema import OffSploitConfig
                validated = OffSploitConfig.from_dict(raw)
                self.config = validated.to_dict()
                self._validated = True
                logger.info("Config doğrulaması başarılı (Pydantic).")
            except Exception as e:
                logger.warning("Config doğrulama hatası: %s — Varsayılan değerler kullanılacak.", e)
                self.config = DEFAULT_CONFIG.copy()
                self._validated = False
        else:
            self.config = DEFAULT_CONFIG.copy()
            self.save()

    def save(self) -> None:
        try:
            self.config_path.write_text(
                json.dumps(self.config, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.error("Config kaydedilemedi: %s", exc)

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, DEFAULT_CONFIG.get(key, default))

    def update(self, data: dict[str, Any]) -> None:
        self.config.update(data)
        # Güncelleme sonrası yeniden doğrula
        try:
            from offsploit.config_schema import OffSploitConfig
            validated = OffSploitConfig.from_dict(self.config)
            self.config = validated.to_dict()
            self._validated = True
        except Exception as e:
            logger.warning("Güncelleme sonrası doğrulama hatası: %s", e)
        self.save()

    def to_dict(self) -> dict[str, Any]:
        merged = DEFAULT_CONFIG.copy()
        merged.update(self.config)
        return merged

    @property
    def is_validated(self) -> bool:
        return self._validated


# Socket.IO Log Handler

class SocketIOLogHandler(logging.Handler):
    """Loglari Socket.IO uzerinden istemciye ileten handler."""

    def __init__(self, socketio_instance: SocketIO) -> None:
        super().__init__()
        self.sio: SocketIO = socketio_instance

    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_entry = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "level": record.levelname,
                "name": record.name,
                "message": self.format(record),
            }
            self.sio.emit("log", log_entry)
        except Exception:
            pass


# Flask App + Socket.IO Initialization

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()

# Güvenlik Sıkılaştırması: CORS ayarlarını çevre değişkeninden veya sadece belli hostlardan al.
cors_origins = os.environ.get("OFFSPLOIT_CORS_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000").split(",")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# --- System Metrics Thread ---
def system_metrics_loop():
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            socketio.emit("system_metrics", {"cpu": cpu, "memory": mem})
        except Exception as e:
            logger.error(f"Metrics error: {e}")
        time.sleep(2)

metrics_thread = threading.Thread(target=system_metrics_loop, daemon=True)
metrics_thread.start()

# --- Terminal PTY State ---
pty_process = None
pty_thread = None

# --- Config Manager & Session Manager ---
config_manager = ConfigManager()
session_manager = SessionManager()
operation_history: list[dict[str, Any]] = []
cancel_flags: dict[str, bool] = {}

# Attach Socket.IO log handler to offsploit loggers
sio_handler = SocketIOLogHandler(socketio)
sio_handler.setFormatter(logging.Formatter("%(name)s | %(message)s"))
sio_handler.setLevel(logging.DEBUG)
logging.getLogger("offsploit").addHandler(sio_handler)

# Izin verilen ayar anahtarlari (whitelist)
ALLOWED_SETTINGS_KEYS: set[str] = {
    "ollama_url", "ollama_model", "ollama_timeout",
    "llm_provider", "api_key",
    "chromadb_path", "collection_name", "exploitdb_root",
    "csv_path", "top_k", "output_dir",
    # v1.0 Settings
    "embedding_provider", "embedding_model",
    "use_docker_sandbox", "docker_memory_limit", "docker_cpu_limit", "docker_timeout",
    "use_swarm", "swarm_max_rounds", "opsec_sensitivity",
    "evasion_level", "state_machine_persist",
}

# Global State Machine (v1.0)
_attack_state_machine = None


@app.after_request
def set_security_headers(response):
    """Tum yanitlara guvenlik header'lari ekler."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.socket.io https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' ws://localhost:* ws://127.0.0.1:*; "
        "img-src 'self' data:;"
    )
    return response


# REST API Routes

@app.route("/")
def index():
    """Ana sayfa (SPA)."""
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """Sistem durumunu kontrol eder."""
    cfg = config_manager.to_dict()

    # LLM Provider kontrolu
    llm_ok = False
    ollama_models: list[str] = []
    try:
        client = LLMClient(
            provider=cfg.get("llm_provider", "ollama"),
            ollama_url=cfg.get("ollama_url", "http://localhost:11434"),
            ollama_model=cfg.get("ollama_model", "qwen2.5-coder:14b"),
            api_key=cfg.get("api_key", "")
        )
        llm_ok = client.health_check()
        if cfg.get("llm_provider", "ollama") == "ollama" and llm_ok:
            import requests as req
            resp = req.get(f"{cfg['ollama_url']}/api/tags", timeout=5)
            if resp.status_code == 200:
                ollama_models = [
                    m.get("name", "") for m in resp.json().get("models", [])
                ]
    except Exception:
        pass

    # ChromaDB kontrolu
    db_count = 0
    db_ok = False
    try:
        import chromadb
        db_path = str(Path(__file__).parent.parent / cfg["chromadb_path"])
        chroma_client = chromadb.PersistentClient(path=db_path)
        col = chroma_client.get_collection(cfg["collection_name"])
        db_count = col.count()
        db_ok = True
    except Exception:
        pass

    # Exploit-DB kontrolu
    root_dir = Path(__file__).parent.parent
    exploitdb_ok = (root_dir / cfg["exploitdb_root"]).exists()
    csv_ok = (root_dir / cfg["csv_path"]).exists()

    return jsonify({
        "ollama": {"connected": llm_ok, "models": ollama_models},
        "chromadb": {"connected": db_ok, "count": db_count},
        "exploitdb": {"exists": exploitdb_ok, "csv_exists": csv_ok},
    })


@app.route("/api/settings", methods=["GET"])
def get_settings():
    """Mevcut ayarlari dondurur."""
    return jsonify(config_manager.to_dict())


@app.route("/api/settings", methods=["POST"])
def save_settings():
    """Ayarlari gunceller (whitelist ile korunmaktadir)."""
    data = request.json
    if data:
        # Sadece izin verilen anahtarlari kabul et
        sanitized = {k: v for k, v in data.items() if k in ALLOWED_SETTINGS_KEYS}
        if sanitized:
            config_manager.update(sanitized)
        else:
            return jsonify({"success": False, "error": "Gecersiz ayar anahtarlari"}), 400
    return jsonify({"success": True, "settings": config_manager.to_dict()})


@app.route("/api/ollama/models")
def get_ollama_models():
    """Ollama'daki mevcut modelleri listeler."""
    cfg = config_manager.to_dict()
    try:
        import requests as req
        resp = req.get(f"{cfg['ollama_url']}/api/tags", timeout=10)
        if resp.status_code == 200:
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            return jsonify({"models": models})
    except Exception:
        pass
    return jsonify({"models": []})


@app.route("/api/db/stats")
def get_db_stats():
    """ChromaDB istatistiklerini dondurur."""
    cfg = config_manager.to_dict()
    try:
        import chromadb
        chroma_client = chromadb.PersistentClient(path=cfg["chromadb_path"])
        col = chroma_client.get_collection(cfg["collection_name"])
        return jsonify({
            "collection": cfg["collection_name"],
            "count": col.count(),
            "path": cfg["chromadb_path"],
        })
    except Exception as exc:
        return jsonify({"error": str(exc), "count": 0})


@app.route("/api/history")
def get_history():
    """Gecmis islem kayitlarini session_db'den dondurur."""
    sessions = session_manager.get_all_sessions(limit=50)
    return jsonify(sessions)


@app.route("/api/session/<session_id>/steps")
def get_session_steps(session_id: str):
    """Bir oturumun loglanmis adimlarini dondurur."""
    steps = session_manager.get_steps(session_id)
    return jsonify({"session_id": session_id, "steps": steps})


# Socket.IO Event Handlers

@socketio.on("connect")
def handle_connect():
    logger.info("Web istemci baglandi.")
    emit("connected", {"status": "ok"})


@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Web istemci ayrildi.")


@socketio.on("upload_nmap")
def handle_upload_nmap(data: dict):
    """Nmap XML dosyasi yuklemesini isler."""
    try:
        content: str = data.get("content", "")
        filename: str = data.get("filename", "scan.xml")

        # Path Traversal korumasi: dosya adini sanitize et
        safe_filename: str = secure_filename(filename)
        if not safe_filename:
            safe_filename = "upload.xml"

        uploads_dir = Path("uploads")
        uploads_dir.mkdir(exist_ok=True)

        filepath = uploads_dir / safe_filename
        filepath.write_text(content, encoding="utf-8")

        logger.info("Nmap dosyasi yuklendi: %s", filepath)
        emit("upload_complete", {
            "success": True,
            "path": str(filepath),
            "filename": filename,
        })
    except Exception as exc:
        logger.error("Dosya yukleme hatasi: %s", exc)
        emit("error", {"message": f"Upload hatasi: {str(exc)}"})


@socketio.on("run_pipeline")
def handle_run_pipeline(data: dict):
    """Tam exploit pipeline'ini arkaplan thread'inde (asyncio ile) calistirir."""
    task_id = str(uuid.uuid4())[:8]
    cancel_flags[task_id] = False

    def pipeline_worker():
        cfg = config_manager.to_dict()
        nmap_path: str = data.get("nmap_path", "")
        lhost: str = data.get("lhost", "")
        rhost: str = data.get("rhost", "")
        lport: str = data.get("lport", "4444")

        def check_cancel() -> bool:
            return cancel_flags.get(task_id, False)
            
        session_id = session_manager.create_session(
            target_ip=rhost,
            config=cfg
        )
        # Store step IDs mapped by step_type for updating
        active_steps = {}

        def on_event(event_type: str, event_data: dict):
            # WebSocket yayini
            socketio.emit("pipeline_event", {
                "type": event_type,
                "data": event_data
            })
            
            # Veritabani loglama
            if event_type == "step_start":
                step_name = event_data.get("message", event_data.get("step"))
                step_type = event_data.get("step", "unknown")
                step_id = session_manager.log_step(
                    session_id=session_id,
                    step_name=step_name,
                    step_type=step_type,
                    status="running"
                )
                active_steps[step_type] = step_id

            elif event_type == "step_complete":
                step_type = event_data.get("step")
                if step_type in active_steps:
                    session_manager.update_step(
                        active_steps[step_type],
                        status="success",
                        output_summary=event_data.get("message"),
                        metadata=event_data
                    )

            elif event_type == "pipeline_error":
                session_manager.finish_session(session_id, status="failed")

            elif event_type == "pipeline_complete":
                session_manager.finish_session(session_id, status="completed")

            socketio.sleep(0)  # Yield for eventlet/gevent

        async def run_async_pipeline():
            try:
                pipeline = AsyncOffSploitPipeline(cfg, on_event, check_cancel)
                # Ensure session ID matches DB
                pipeline._session_id = session_id
                
                # Sadece asenkron run cagirilir. Evazyon vb ileride eklenebilir.
                result = await pipeline.run(
                    nmap_xml=nmap_path,
                    lhost=lhost,
                    lport=lport,
                )
                
                if not result.get("success"):
                    session_manager.finish_session(session_id, status="failed")
                    socketio.emit("pipeline_complete", {"success": False, "message": result.get("error")})
                else:
                    socketio.emit("pipeline_complete", result)

            except Exception as exc:
                import traceback
                error_trace = traceback.format_exc()
                logger.critical("Pipeline thread hatasi: %s\n%s", exc, error_trace)
                session_manager.finish_session(session_id, status="failed")
                socketio.emit("error", {"message": f"{str(exc)} \n\nDetails: {error_trace}"})
                socketio.emit("pipeline_complete", {"success": False, "message": str(exc)})

        # Run asyncio event loop inside this thread
        import asyncio
        asyncio.run(run_async_pipeline())

    thread = threading.Thread(target=pipeline_worker, daemon=True)
    thread.start()
    emit("task_started", {"task_id": task_id})


@socketio.on("search_exploit")
def handle_search_exploit(data: dict):
    """Manuel exploit aramasini arkaplan thread'inde calistirir."""
    query: str = data.get("query", "")
    top_k: int = int(data.get("top_k", 2))

    if not query:
        emit("error", {"message": "Arama sorgusu bos"})
        return

    def search_worker():
        cfg = config_manager.to_dict()
        try:
            socketio.emit("search_status", {"status": "running"})
            rag = OffSploitRAG(
                db_path=cfg["chromadb_path"],
                exploitdb_root=cfg["exploitdb_root"],
                top_k=top_k,
            )
            matches = rag.search(query, top_k=top_k)

            results = [
                {
                    "exploit_id": m.exploit_id,
                    "description": m.description,
                    "file_path": m.file_path,
                    "platform": m.platform,
                    "type": m.exploit_type,
                    "distance": round(m.distance, 4),
                    "source_code": m.source_code[:10000] if m.source_code else "",
                    "has_source": bool(m.source_code),
                }
                for m in matches
            ]
            socketio.emit("search_results", {"query": query, "results": results})
        except Exception as exc:
            logger.error("Arama hatasi: %s", exc)
            socketio.emit("search_results", {
                "query": query, "results": [], "error": str(exc),
            })

    thread = threading.Thread(target=search_worker, daemon=True)
    thread.start()


@socketio.on("adapt_exploit")
def handle_adapt_exploit(data: dict):
    """Secilen exploit'i LLM ile uyarlar."""
    source_code: str = data.get("source_code", "")
    lhost: str = data.get("lhost", "")
    rhost: str = data.get("rhost", "")
    lport: str = data.get("lport", "4444")
    model: str = data.get("model", "")

    if not source_code:
        emit("error", {"message": "Kaynak kodu bos"})
        return

    def adapt_worker():
        cfg = config_manager.to_dict()
        try:
            socketio.emit("adapt_status", {"status": "running"})
            llm = LLMClient(
                provider=cfg.get("llm_provider", "ollama"),
                ollama_url=cfg["ollama_url"],
                ollama_model=model or cfg["ollama_model"],
                ollama_timeout=int(cfg["ollama_timeout"]),
                api_key=cfg.get("api_key", "")
            )
            result = llm.adapt_exploit(source_code, lhost, rhost, lport)
            socketio.emit("adapt_result", {"success": True, "code": result})
        except Exception as exc:
            logger.error("Uyarlama hatasi: %s", exc)
            socketio.emit("adapt_result", {
                "success": False, "message": str(exc),
            })

    thread = threading.Thread(target=adapt_worker, daemon=True)
    thread.start()


@socketio.on("update_db")
def handle_update_db(data: dict):
    """ChromaDB veritabanini arkaplan thread'inde gunceller."""
    csv_path: str = data.get("csv_path", "")

    def ingest_worker():
        cfg = config_manager.to_dict()
        try:
            socketio.emit("db_update_status", {
                "status": "running", "message": "Ingest basliyor...",
            })

            def progress_cb(current: int, total: int, message: str) -> None:
                pct = round(current / total * 100, 1) if total > 0 else 0
                socketio.emit("db_update_progress", {
                    "current": current,
                    "total": total,
                    "percentage": pct,
                    "message": message,
                })

            ingestor = Ingestor(
                csv_path=str(Path(__file__).parent.parent / (csv_path or cfg["csv_path"])),
                db_path=cfg["chromadb_path"],
                collection_name=cfg["collection_name"],
                progress_callback=progress_cb,
            )
            count: int = ingestor.ingest()

            socketio.emit("db_update_status", {
                "status": "done",
                "message": f"Tamamlandi: {count} exploit aktarildi",
                "count": count,
            })

            operation_history.append({
                "id": str(uuid.uuid4())[:8],
                "type": "db_update",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "count": count,
                "success": True,
            })
        except Exception as exc:
            logger.error("DB guncelleme hatasi: %s", exc, exc_info=True)
            socketio.emit("db_update_status", {
                "status": "error", "message": str(exc),
            })

    thread = threading.Thread(target=ingest_worker, daemon=True)
    thread.start()


@socketio.on("cancel_operation")
def handle_cancel(data: dict):
    """Calisan islemi iptal eder."""
    task_id: str = data.get("task_id", "")
    if task_id in cancel_flags:
        cancel_flags[task_id] = True
        emit("operation_cancelled", {"task_id": task_id})
        logger.info("Islem iptal edildi: %s", task_id)


# ═══════════════════════════════════════════════
# v1.1 Terminal Socket.IO Handlers (Subprocess)
# ═══════════════════════════════════════════════

def pty_reader_loop():
    """Background thread to read from PTY subprocess and send to client"""
    global pty_process
    while pty_process and pty_process.poll() is None:
        try:
            # Read a chunk from the process
            output = os.read(pty_process.stdout.fileno(), 1024)
            if output:
                socketio.emit("pty_output", {"output": output.decode("utf-8", "replace")})
        except Exception:
            break

@socketio.on("pty_start")
def handle_pty_start(data: dict):
    global pty_process, pty_thread
    import subprocess
    if pty_process and pty_process.poll() is None:
        return # Already running

    # Use cmd.exe on Windows as the default shell
    shell_cmd = "cmd.exe"
    if os.name != "nt":
        shell_cmd = "/bin/bash"

    try:
        pty_process = subprocess.Popen(
            [shell_cmd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        pty_thread = threading.Thread(target=pty_reader_loop, daemon=True)
        pty_thread.start()
        logger.info(f"Terminal session started with {shell_cmd}")
    except Exception as e:
        emit("pty_output", {"output": f"Failed to start terminal: {str(e)}\r\n"})

@socketio.on("pty_input")
def handle_pty_input(data: dict):
    global pty_process
    if pty_process and pty_process.poll() is None:
        input_data = data.get("input", "")
        if input_data:
            with contextlib.suppress(Exception):
                os.write(pty_process.stdin.fileno(), input_data.encode("utf-8"))

@socketio.on("pty_resize")
def handle_pty_resize(data: dict):
    # Standard python subprocess doesn't support PTY resizing.
    # In a full Linux environment, we would use the `pty` module and `fcntl.ioctl`.
    # For this simulated environment, we silently ignore resizing requests.
    pass


# ═══════════════════════════════════════════════
# v1.0 Socket.IO Handlers: State Machine
# ═══════════════════════════════════════════════

@socketio.on("register_shell")
def handle_register_shell(data: dict):
    """Yeni shell kaydeder ve state machine'i gunceller."""
    global _attack_state_machine
    from offsploit.state_machine import AccessLevel, AttackStateMachine, PivotNode

    if _attack_state_machine is None:
        cfg = config_manager.to_dict()
        _attack_state_machine = AttackStateMachine(
            on_event=lambda e, d: socketio.emit(e, d),
            persist_path=str(Path(cfg["output_dir"]) / "state_machine.json") if cfg.get("state_machine_persist") else None,
        )

    try:
        access = AccessLevel(data.get("access_level", "user"))
    except ValueError:
        access = AccessLevel.USER

    pivot = PivotNode(
        ip=data.get("ip", ""),
        hostname=data.get("hostname", ""),
        os=data.get("os", ""),
        arch=data.get("arch", "x64"),
        access_level=access,
        shell_type=data.get("shell_type", "bash"),
    )
    _attack_state_machine.register_shell(pivot)
    emit("shell_registered", pivot.to_dict())
    emit("state_update", _attack_state_machine.get_status())


@socketio.on("plan_next_move")
def handle_plan_next_move(data: dict):
    """State machine'den sonraki adimi planlar."""
    global _attack_state_machine
    if _attack_state_machine is None:
        emit("error", {"message": "State machine henuz baslatilmadi."})
        return
    plan = _attack_state_machine.plan_next_move()
    emit("next_move_plan", plan)


@socketio.on("get_attack_graph")
def handle_get_attack_graph(data: dict):
    """Saldiri grafigini dondurur."""
    global _attack_state_machine
    if _attack_state_machine is None:
        emit("attack_graph", {"nodes": [], "edges": [], "current_state": "initial"})
        return
    emit("attack_graph", _attack_state_machine.get_attack_graph())


@socketio.on("get_state_status")
def handle_get_state_status(data: dict):
    """State machine durumunu dondurur."""
    global _attack_state_machine
    if _attack_state_machine is None:
        emit("state_update", {"state": "initial", "pivot_count": 0})
        return
    emit("state_update", _attack_state_machine.get_status())


# ═══════════════════════════════════════════════
# v1.0 Socket.IO Handlers: BloodHound Ingest
# ═══════════════════════════════════════════════

@socketio.on("ingest_bloodhound")
def handle_ingest_bloodhound(data: dict):
    """BloodHound JSON verilerini ChromaDB'ye aktarir."""
    folder_path = data.get("folder_path", "")
    if not folder_path:
        emit("error", {"message": "BloodHound dizin yolu bos."})
        return

    def bh_ingest_worker():
        cfg = config_manager.to_dict()
        try:
            socketio.emit("bh_ingest_status", {"status": "running", "message": "BloodHound ingest basliyor..."})
            from offsploit.chromadb_ingest import Ingestor
            ingestor = Ingestor(
                db_path=cfg["chromadb_path"],
                config=cfg,
                exploitdb_root=cfg.get("exploitdb_root", "exploitdb"),
            )
            count = ingestor.ingest_bloodhound(folder_path)
            socketio.emit("bh_ingest_status", {
                "status": "done",
                "message": f"BloodHound ingest tamamlandi: {count} AD dokumani aktarildi.",
                "count": count,
            })
        except Exception as exc:
            logger.error("BloodHound ingest hatasi: %s", exc, exc_info=True)
            socketio.emit("bh_ingest_status", {"status": "error", "message": str(exc)})

    thread = threading.Thread(target=bh_ingest_worker, daemon=True)
    thread.start()


# Main Entry Point

def main() -> None:
    """Web uygulamasini baslatir."""
    import argparse

    arg_parser = argparse.ArgumentParser(
        description="OffSploit Web UI",
    )
    arg_parser.add_argument(
        "--port", type=int, default=5000, help="Sunucu portu (varsayilan: 5000)"
    )
    arg_parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Sunucu adresi"
    )
    arg_parser.add_argument(
        "--debug", action="store_true", help="Debug modu"
    )
    args = arg_parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s | %(name)-24s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # Uploads dizinini olustur
    Path("uploads").mkdir(exist_ok=True)
    Path(config_manager.get("output_dir", "./output")).mkdir(
        parents=True, exist_ok=True
    )

    print()
    print("  OffSploit Web UI v1.0")
    print(f"  http://localhost:{args.port}")
    print()

    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()
