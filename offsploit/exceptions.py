#!/usr/bin/env python3
"""
OffSploit - Özel Hata Sınıfları (Custom Exceptions)
=====================================================
Tüm OffSploit modüllerinde kullanılan, alan-spesifik hata
sınıfları. Genel Exception kullanımını ortadan kaldırarak
hata ayıklamayı ve kullanıcı dostu mesajları kolaylaştırır.
"""


class OffSploitError(Exception):
    """Tüm OffSploit hatalarının taban sınıfı.

    Bu sınıftan türeyen her hata, OffSploit'a özgü bir sorunu
    temsil eder ve genel Exception'lardan ayrıştırılabilir.
    """

    def __init__(self, message: str = "", detail: str = "") -> None:
        self.detail = detail
        super().__init__(message)


class NmapParseError(OffSploitError):
    """Nmap XML dosyası ayrıştırma sırasında oluşan hatalar.

    Örnekler:
        - XML dosyası bulunamadı
        - Geçersiz XML sözdizimi
        - Beklenen elementler eksik
    """


class RAGSearchError(OffSploitError):
    """ChromaDB veya embedding modeli ile ilgili hatalar.

    Örnekler:
        - ChromaDB koleksiyonu bulunamadı
        - Embedding modeli yüklenemedi
        - Sorgu çalıştırma hatası
    """


class OllamaConnectionError(OffSploitError):
    """Ollama sunucusuna bağlantı kurulamadığında fırlatılır.

    Örnekler:
        - Sunucu kapalı
        - Yanlış URL
        - Ağ erişim hatası
    """


class OllamaTimeoutError(OffSploitError):
    """Ollama API isteği zaman aşımına uğradığında fırlatılır.

    Attributes:
        timeout_seconds: Aşılan zaman aşımı değeri.
    """

    def __init__(self, message: str = "", timeout_seconds: int = 0) -> None:
        self.timeout_seconds = timeout_seconds
        super().__init__(message)


class OllamaAPIError(OffSploitError):
    """Ollama API'sinden beklenmeyen HTTP yanıtı alındığında fırlatılır.

    Attributes:
        status_code: HTTP durum kodu.
        response_body: Yanıt gövdesi (kısaltılmış).
    """

    def __init__(
        self, message: str = "", status_code: int = 0, response_body: str = ""
    ) -> None:
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(message)


class CompilerError(OffSploitError):
    """Derleme işlemi sırasında oluşan hatalar.

    Örnekler:
        - gcc/g++ bulunamadı
        - Derleme zaman aşımı
        - Sözdizimi hatası (compiler error output)
    """


class ConfigError(OffSploitError):
    """Yapılandırma dosyası ile ilgili hatalar.

    Örnekler:
        - config.json okunamadı
        - Gerekli ayar eksik
        - Geçersiz değer
    """


class IngestError(OffSploitError):
    """ChromaDB veri aktarımı (ingest) sırasında oluşan hatalar.

    Örnekler:
        - CSV dosyası bulunamadı
        - Gerekli sütunlar eksik
        - Embedding oluşturma hatası
    """


class DockerSandboxError(OffSploitError):
    """Docker sandbox işlemleri sırasında oluşan hatalar.

    Örnekler:
        - Docker daemon'a bağlanılamadı
        - Container oluşturma/çalıştırma hatası
        - Sandbox zaman aşımı
    """


class SwarmAgentError(OffSploitError):
    """Multi-Agent (Swarm) iş akışı sırasında oluşan hatalar.

    Örnekler:
        - Ajan iletişim hatası
        - OPSEC doğrulama döngüsü tükendi
        - Ajan yanıt ayrıştırma hatası
    """


class EvasionError(OffSploitError):
    """Polimorfik kod ve evasion motoru sırasında oluşan hatalar.

    Örnekler:
        - Kod dönüşümü başarısız
        - Indirect syscall üretim hatası
        - Polimorfik mutasyon hatası
    """


class StateMachineError(OffSploitError):
    """Otonom pivoting state machine sırasında oluşan hatalar.

    Örnekler:
        - Geçersiz durum geçişi
        - Pivot node kaydı hatası
        - Saldırı grafiği oluşturma hatası
    """


class PayloadError(OffSploitError):
    """Post-exploitation payload motoru sırasında oluşan hatalar.

    Örnekler:
        - Payload enjeksiyon hatası
        - Desteklenmeyen mimari
        - Shellcode encoding hatası
    """


class AttackCorrelationError(OffSploitError):
    """BloodHound + Nmap saldırı korelasyonu sırasında oluşan hatalar.

    Örnekler:
        - AD verisi eksik veya geçersiz
        - Korelasyon eşleşmesi bulunamadı
        - Zincirleme saldırı planı oluşturma hatası
    """
