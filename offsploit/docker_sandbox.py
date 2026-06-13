#!/usr/bin/env python3
"""
OffSploit - Docker Sandbox (Self-Healing) v1.0
================================================
Docker SDK for Python kullanarak exploit kodlarını izole container'larda
derleyip çalıştıran, hata alınırsa stderr'i LLM'e geri besleyerek
otonom onarım döngüsü sağlayan sandbox modülü.
"""

import contextlib
import io
import logging
import tarfile
import time
from dataclasses import dataclass

from offsploit.exceptions import DockerSandboxError

logger = logging.getLogger("offsploit.docker_sandbox")

# Docker SDK lazy import
_docker = None


def _get_docker():
    """Docker SDK'yı lazy-load eder."""
    global _docker
    if _docker is None:
        try:
            import docker
            _docker = docker
        except ImportError:
            raise DockerSandboxError(
                "Docker SDK yüklü değil. 'pip install docker' ile yükleyin.",
                detail="docker paketi bulunamadı"
            )
    return _docker


@dataclass
class SandboxResult:
    """Docker sandbox çalıştırma sonucu.

    Attributes:
        success: İşlem başarılı mı (exit_code == 0).
        stdout: Standart çıktı.
        stderr: Hata çıktısı.
        exit_code: Container çıkış kodu.
        duration: İşlem süresi (saniye).
        language: Derlenen dilin adı.
    """
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration: float = 0.0
    language: str = ""


# Dil → Docker imaj eşlemeleri
LANGUAGE_IMAGES: dict[str, dict] = {
    "c": {
        "image": "gcc:latest",
        "compile_cmd": "gcc /tmp/exploit.c -o /tmp/exploit.out -w -lpthread 2>&1",
        "run_cmd": "/tmp/exploit.out",
        "source_file": "/tmp/exploit.c",
        "ext": ".c",
    },
    "cpp": {
        "image": "gcc:latest",
        "compile_cmd": "g++ /tmp/exploit.cpp -o /tmp/exploit.out -w -lpthread 2>&1",
        "run_cmd": "/tmp/exploit.out",
        "source_file": "/tmp/exploit.cpp",
        "ext": ".cpp",
    },
    "python": {
        "image": "python:3.12-slim",
        "compile_cmd": "python3 -m py_compile /tmp/exploit.py 2>&1",
        "run_cmd": "python3 /tmp/exploit.py",
        "source_file": "/tmp/exploit.py",
        "ext": ".py",
    },
}


class DockerSandbox:
    """İzole Docker container'larında exploit derleme ve çalıştırma.

    Güvenlik önlemleri:
        - Ağ erişimi yok (network_mode=none)
        - Bellek limiti (varsayılan 256m)
        - CPU limiti (varsayılan 0.5 core)
        - Zaman aşımı desteği
    """

    def __init__(
        self,
        memory_limit: str = "256m",
        cpu_limit: float = 0.5,
        timeout: int = 30,
        max_containers: int = 3,
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.timeout = timeout
        self.max_containers = max_containers
        self._client = None
        self._active_containers: int = 0

    def _get_client(self):
        """Docker client'ını başlatır (lazy)."""
        if self._client is None:
            docker = _get_docker()
            try:
                self._client = docker.from_env()
                # Bağlantı testi
                self._client.ping()
                logger.info("Docker daemon'a bağlanıldı.")
            except Exception as exc:
                logger.error("Docker daemon'a bağlanılamadı: %s", exc)
                raise DockerSandboxError(
                    f"Docker daemon'a bağlanılamadı: {exc}",
                    detail="Docker servisinin çalıştığından emin olun."
                ) from exc
        return self._client

    def is_available(self) -> bool:
        """Docker daemon'ın erişilebilir olup olmadığını kontrol eder."""
        try:
            self._get_client()
            return True
        except (DockerSandboxError, Exception):
            return False

    def _run_container(
        self,
        image: str,
        command: str,
        source_code: str,
        source_file: str,
    ) -> tuple[int, str, str]:
        """Bir Docker container'ı oluşturup çalıştırır.

        Returns:
            Tuple[exit_code, stdout, stderr]
        """
        client = self._get_client()
        container = None
        start_time = time.time()

        try:
            if self._active_containers >= self.max_containers:
                raise DockerSandboxError(
                    f"Eşzamanlı container limiti aşıldı ({self.max_containers})"
                )

            self._active_containers += 1

            # Container oluştur (henüz başlatılmadı)
            try:
                container = client.containers.create(
                    image=image,
                    command=f'/bin/bash -c "{command}"',
                    network_mode="none",
                    mem_limit=self.memory_limit,
                    nano_cpus=int(self.cpu_limit * 1e9),
                    detach=True,
                    stdin_open=False,
                    tty=False,
                )
            except _get_docker().errors.ImageNotFound:
                logger.info("İmaj bulunamadı, çekiliyor: %s", image)
                client.images.pull(image)
                container = client.containers.create(
                    image=image,
                    command=f'/bin/bash -c "{command}"',
                    network_mode="none",
                    mem_limit=self.memory_limit,
                    nano_cpus=int(self.cpu_limit * 1e9),
                    detach=True,
                    stdin_open=False,
                    tty=False,
                )

            # Dosyayı tar arşivine çevir ve container içine kopyala
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                code_bytes = source_code.encode('utf-8')
                tarinfo = tarfile.TarInfo(name=source_file.lstrip('/'))
                tarinfo.size = len(code_bytes)
                tarinfo.mtime = int(time.time())
                tar.addfile(tarinfo, io.BytesIO(code_bytes))
            tar_stream.seek(0)

            container.put_archive("/", tar_stream)

            # Şimdi çalıştır
            container.start()

            # Zaman aşımı ile bekle
            try:
                result = container.wait(timeout=self.timeout)
                exit_code = result.get("StatusCode", -1)
            except Exception:
                # Zaman aşımı — container'ı öldür
                with contextlib.suppress(Exception):
                    container.kill()
                return -1, "", "Container zaman aşımına uğradı."

            # Logları al
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            duration = time.time() - start_time
            logger.info(
                "Container tamamlandı: exit_code=%d, süre=%.1fs",
                exit_code, duration
            )

            return exit_code, stdout.strip(), stderr.strip()

        except DockerSandboxError:
            raise
        except Exception as exc:
            logger.error("Docker container hatası: %s", exc)
            raise DockerSandboxError(f"Container çalıştırma hatası: {exc}") from exc
        finally:
            # Container temizliği
            if container:
                with contextlib.suppress(Exception):
                    container.remove(force=True)
            self._active_containers = max(0, self._active_containers - 1)

    def compile_in_sandbox(self, source_code: str, language: str) -> SandboxResult:
        """Exploit kodunu Docker container'ında derler.

        Args:
            source_code: Derlenecek kaynak kod.
            language: Dil ('c', 'cpp', 'python').

        Returns:
            SandboxResult: Derleme sonucu.
        """
        lang_key = language.lower().replace("c++", "cpp")

        if lang_key not in LANGUAGE_IMAGES:
            return SandboxResult(
                success=True,
                stdout=f"{language} derleme gerektirmez.",
                language=language
            )

        lang_config = LANGUAGE_IMAGES[lang_key]
        logger.info(
            "Docker sandbox derleme başlıyor: %s (imaj: %s)",
            language, lang_config["image"]
        )

        start_time = time.time()
        try:
            exit_code, stdout, stderr = self._run_container(
                image=lang_config["image"],
                command=lang_config["compile_cmd"],
                source_code=source_code,
                source_file=lang_config["source_file"],
            )

            duration = time.time() - start_time
            success = exit_code == 0

            return SandboxResult(
                success=success,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
                language=language,
            )

        except DockerSandboxError as e:
            return SandboxResult(
                success=False,
                stderr=str(e),
                duration=time.time() - start_time,
                language=language,
            )

    def run_in_sandbox(self, source_code: str, language: str, timeout: int | None = None) -> SandboxResult:
        """Exploit kodunu Docker container'ında çalıştırır (derleme + çalışma).

        Args:
            source_code: Çalıştırılacak kaynak kod.
            language: Dil ('c', 'cpp', 'python').
            timeout: Özel zaman aşımı (saniye).

        Returns:
            SandboxResult: Çalıştırma sonucu.
        """
        lang_key = language.lower().replace("c++", "cpp")

        if lang_key not in LANGUAGE_IMAGES:
            return SandboxResult(
                success=False,
                stderr=f"Desteklenmeyen dil: {language}",
                language=language
            )

        lang_config = LANGUAGE_IMAGES[lang_key]

        # C/C++ için: derle + çalıştır
        if lang_key in ("c", "cpp"):
            full_cmd = f"{lang_config['compile_cmd']} && {lang_config['run_cmd']}"
        else:
            full_cmd = lang_config["run_cmd"]

        old_timeout = self.timeout
        if timeout:
            self.timeout = timeout

        start_time = time.time()
        try:
            exit_code, stdout, stderr = self._run_container(
                image=lang_config["image"],
                command=full_cmd,
                source_code=source_code,
                source_file=lang_config["source_file"],
            )

            duration = time.time() - start_time
            return SandboxResult(
                success=exit_code == 0,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
                language=language,
            )
        except DockerSandboxError as e:
            return SandboxResult(
                success=False,
                stderr=str(e),
                duration=time.time() - start_time,
                language=language,
            )
        finally:
            self.timeout = old_timeout

    def self_healing_loop(
        self,
        source_code: str,
        language: str,
        llm_fix_callback,
        max_retries: int = 3,
    ) -> tuple[bool, str, str]:
        """Otonom onarım döngüsü: Derle → Hata → LLM Onar → Tekrar Derle.

        Args:
            source_code: Başlangıç kaynak kodu.
            language: Dil.
            llm_fix_callback: Hata mesajını alıp düzeltilmiş kodu döndüren callable.
                              İmza: (code: str, error: str) -> str
            max_retries: Maksimum onarım denemesi.

        Returns:
            Tuple[success, final_code, final_message]
        """
        current_code = source_code

        for attempt in range(max_retries + 1):
            result = self.compile_in_sandbox(current_code, language)

            if result.success:
                msg = f"Kod başarıyla derlendi (Docker sandbox, deneme {attempt + 1})."
                logger.info(msg)
                return True, current_code, msg

            error_msg = result.stderr or result.stdout or "Bilinmeyen derleme hatası"
            # Hata mesajını kısalt (LLM'i boğmasın)
            trimmed_error = error_msg[-2000:] if len(error_msg) > 2000 else error_msg

            if attempt < max_retries:
                logger.info(
                    "Docker sandbox derleme hatası (deneme %d/%d). LLM onarımı başlıyor...",
                    attempt + 1, max_retries
                )
                try:
                    fixed_code = llm_fix_callback(current_code, trimmed_error)
                    if fixed_code and fixed_code.strip():
                        current_code = fixed_code
                    else:
                        logger.warning("LLM boş onarım yanıtı döndürdü.")
                except Exception as exc:
                    logger.error("LLM onarım hatası: %s", exc)

        return False, current_code, f"Docker sandbox: {max_retries} deneme sonrası derleme başarısız. Son hata: {trimmed_error}"
