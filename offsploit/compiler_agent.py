#!/usr/bin/env python3
"""
OffSploit - Compiler Agent (Self-Healing)
===========================================
C/C++ gibi derlenebilir exploit kodlarını arka planda
derleyip syntax hatalarını ve eksik kütüphaneleri tespit eden,
otonom hata onarım (Self-Healing) döngüsü için altyapı sunan modül.
"""

import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("offsploit.compiler")


class CompilerAgent:
    """Exploit kodunu derleyip hataları tespit eden ajan."""

    @staticmethod
    def compile_and_check(source_code: str, language: str = "c", timeout: int = 15) -> tuple[bool, str, str | None]:
        """
        Kodu geçici bir dosyaya yazıp gcc/g++ ile derlemeyi dener.

        Args:
            source_code: Derlenecek kaynak kod.
            language: 'c' veya 'cpp'.
            timeout: Derleme için maksimum süre.

        Returns:
            Tuple[bool, str, str]: (Derleme Başarılı Mı, Mesaj/Hata Çıktısı, Çıktı Dosyası Yolu veya None)
        """
        # Python veya derlenmeyen diller için pas geç.
        if language not in ["c", "cpp"]:
            return True, f"{language} derlenen bir dil degil, atlanildi.", None

        # Derleyici komutunu belirle
        compiler = "gcc" if language == "c" else "g++"
        ext = ".c" if language == "c" else ".cpp"

        logger.info("Derleme testi basliyor: %s (Timeout: %ss)", compiler, timeout)

        # Geçici dizinde dosya oluştur
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                source_path = Path(temp_dir) / f"exploit{ext}"
                output_path = Path(temp_dir) / "exploit.out"

                source_path.write_text(source_code, encoding="utf-8")

                # Standart C exploitleri için sık kullanılan flagler
                # (-Wno-format-security -w vs uyarıları susturmak için eklenebilir)
                compile_cmd = [compiler, str(source_path), "-o", str(output_path), "-w"]

                # İhtiyaca göre -lssl -lcrypto -lpthread -lws2_32 gibi genel kütüphaneler de eklenebilir.
                # Şimdilik yalın derlemeyi deniyoruz.

                result = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                if result.returncode == 0:
                    logger.info("[+] Kod başarıyla derlendi!")
                    # Not: Geçici dizin with bloğu çıkışında silineceğinden output_path artık geçersiz olur.
                    # Ancak buradaki asıl amacımız sadece kodun *derlenebilir* olduğunu doğrulamaktır.
                    return True, "Kod basariyla derlendi.", None
                else:
                    error_output = result.stderr.strip()
                    logger.warning("[-] Derleme Hatası! (Return code: %d)", result.returncode)
                    # Sadece hatanın önemli kısmını al (çok uzunsa LLM'i boğmasın)
                    trimmed_error = error_output[-2000:] if len(error_output) > 2000 else error_output
                    return False, trimmed_error, None

        except subprocess.TimeoutExpired:
            logger.error("[-] Derleme zaman aşımına uğradı.")
            return False, "Derleme islemi zaman asimina ugradi.", None
        except FileNotFoundError:
            logger.error("[-] Sistemde '%s' bulunamadı. Derleme atlanıyor.", compiler)
            return True, f"Sistemde {compiler} bulunamadi, derleme dogrulamasi atlandi.", None
        except Exception as exc:
            logger.error("[-] Beklenmeyen derleme hatası: %s", exc)
            return False, f"Beklenmeyen derleme hatasi: {exc}", None

    @staticmethod
    def check_python_syntax(source_code: str) -> tuple[bool, str, str | None]:
        """
        Python kodunun syntax olarak geçerli olup olmadığını py_compile ile kontrol eder.
        Özellikle Python 2 vs Python 3 farklılıklarındaki print hatalarını yakalamak için.
        """
        import py_compile
        logger.info("Python Syntax kontrolü başlıyor...")
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as tmp:
                tmp.write(source_code)
                tmp_path = tmp.name

            try:
                py_compile.compile(tmp_path, doraise=True)
                logger.info("[+] Python kodunda syntax hatası bulunamadı.")
                return True, "Kod başarıyla derlendi (Syntax kontrolünden geçti).", None
            except py_compile.PyCompileError as e:
                logger.warning("[-] Python Syntax Hatası!")
                error_msg = str(e)
                trimmed_error = error_msg[-2000:] if len(error_msg) > 2000 else error_msg
                return False, f"SyntaxError: {trimmed_error}", None
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        except Exception as exc:
            logger.error("[-] Beklenmeyen Python kontrol hatası: %s", exc)
            return False, f"Beklenmeyen python kontrol hatasi: {exc}", None

    @staticmethod
    def check_python_logic(source_code: str, timeout: int = 15) -> tuple[bool, str, str | None]:
        """
        Python kodunda mantıksal hataları (tanımsız değişkenler, eksik importlar)
        çalıştırmadan (statik analiz ile) Flake8 kullanarak kontrol eder.
        Sadece kodu bozacak kritik (E ve F) hataları yakalar.
        """
        import os
        import subprocess
        import tempfile

        logger.info("Python Linter (Flake8) kontrolü başlıyor...")
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as tmp:
                tmp.write(source_code)
                tmp_path = tmp.name

            try:
                # Sadece kritik hataları seç:
                # E9: SyntaxError, IndentationError
                # F4: Import errors (Unused, missing)
                # F8: Name errors (Undefined variables)
                flake8_cmd = [
                    "flake8", tmp_path,
                    "--select=E9,F4,F8",
                    "--show-source"
                ]

                result = subprocess.run(
                    flake8_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

                if result.returncode == 0:
                    logger.info("[+] Python kodunda kritik mantık hatası bulunamadı.")
                    return True, "Kod başarıyla Flake8 testinden geçti.", None
                else:
                    error_output = result.stdout.strip() or result.stderr.strip()
                    logger.warning("[-] Python Mantık Hatası (Linter) Tespit Edildi!")
                    # Kullanıcı dostu olmayan tam dosya yolunu temizle
                    cleaned_error = error_output.replace(tmp_path, "exploit.py")
                    trimmed_error = cleaned_error[-2000:] if len(cleaned_error) > 2000 else cleaned_error
                    return False, f"Flake8 (Linter) Hatası:\n{trimmed_error}", None
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        except subprocess.TimeoutExpired:
            logger.error("[-] Flake8 zaman aşımına uğradı.")
            return False, "Flake8 analizi zaman asimina ugradi.", None
        except FileNotFoundError:
            logger.warning("[-] Sistemde Flake8 yüklü değil, mantık analizi atlanıyor.")
            return True, "Flake8 yuklu olmadigi icin linter kontrolu atlandi.", None
        except Exception as exc:
            logger.error("[-] Beklenmeyen Flake8 hatası: %s", exc)
            return False, f"Beklenmeyen linter hatasi: {exc}", None
