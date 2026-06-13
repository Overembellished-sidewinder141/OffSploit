#!/usr/bin/env python3
"""
OffSploit - Pre-Flight Check Module
=====================================
Exploit adaptasyonu ve çalıştırılmasından önce hedefin
ve belirtilen servisin ağ üzerinde erişilebilir olup olmadığını
otonom olarak test eder.
"""

import logging
import socket

logger = logging.getLogger("offsploit.preflight")


class PreFlightCheck:
    """Hedefin erişilebilirliğini test eden yardımcı sınıf."""

    @staticmethod
    def check_target_alive(rhost: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
        """
        Verilen hedef IP ve porta TCP bağlantısı açmayı dener.

        Args:
            rhost: Hedef IP veya hostname.
            port: Test edilecek port.
            timeout: Bağlantı zaman aşımı süresi (saniye).

        Returns:
            Tuple[bool, str]: (Başarılı mı, Durum/Hata Mesajı)
        """
        logger.info("Pre-Flight Check başlatılıyor: %s:%s (Timeout: %ss)", rhost, port, timeout)

        try:
            # IPv4 ve TCP socket oluştur
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((rhost, port))

                if result == 0:
                    logger.info("[+] Hedef %s:%s ERİŞİLEBİLİR durumda.", rhost, port)
                    return True, f"Hedef {rhost}:{port} erisilebilir ve yanit veriyor."
                else:
                    logger.warning("[-] Hedef %s:%s KAPALI veya filtreli (Hata kodu: %d).", rhost, port, result)
                    return False, f"Hedef {rhost}:{port} yanit vermiyor (Kapali/Filtreli)."

        except TimeoutError:
            logger.warning("[-] Hedef %s:%s ZAMAN AŞIMINA uğradı.", rhost, port)
            return False, f"Baglanti {timeout} saniye icinde zaman asimina ugradi."
        except socket.gaierror:
            logger.error("[-] Hedef %s için geçersiz adres/isim.", rhost)
            return False, f"Gecersiz IP adresi veya hostname: {rhost}"
        except Exception as exc:
            logger.error("[-] Beklenmeyen Pre-Flight Check hatası: %s", exc)
            return False, f"Beklenmeyen ag hatasi: {exc}"

