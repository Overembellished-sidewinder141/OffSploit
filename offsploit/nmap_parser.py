#!/usr/bin/env python3
"""
OffSploit - Nmap XML Ayrıştırıcı (Scanner Modülü)
===================================================
Nmap XML çıktısını parse ederek açık portlardaki servis bilgilerini
aranabilir string listesine dönüştürür.
"""

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from offsploit.exceptions import NmapParseError

logger = logging.getLogger("offsploit.nmap")


@dataclass
class ServiceInfo:
    """Tek bir açık port hakkında toplanan servis bilgisi.

    Attributes:
        port:       Port numarası.
        protocol:   Protokol (tcp / udp).
        name:       Servis adı (örn. "ftp", "ssh").
        product:    Ürün adı (örn. "vsftpd", "OpenSSH").
        version:    Sürüm bilgisi (örn. "2.3.4", "7.2p2").
        query:      ChromaDB araması için birleştirilmiş sorgu metni.
    """

    port: int
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    ostype: str = ""
    query: str = field(init=False, default="")

    def __post_init__(self) -> None:
        """Sorgu metnini otomatik olarak oluşturur."""
        parts: list[str] = []
        if self.product:
            parts.append(self.product)
        elif self.name:
            parts.append(self.name)
        if self.version:
            parts.append(self.version)
        if self.extrainfo:
            # Sadece kritik olabilecek detayları alıp temizleyebiliriz ama hepsini koymak RAG için iyidir.
            parts.append(self.extrainfo)
        if self.ostype:
            parts.append(self.ostype)

        self.query = " ".join(parts).strip()


class NmapParser:
    """Nmap XML çıktısını ayrıştırıp servis bilgilerini çıkaran sınıf.

    Attributes:
        xml_path: Nmap XML dosyasının yolu.
    """

    def __init__(self, xml_path: str) -> None:
        self.xml_path: Path = Path(xml_path)
        self._tree: ET.ElementTree | None = None

    # Dahili yardımcılar

    def _load_xml(self) -> ET.ElementTree:
        """XML dosyasını yükler ve ayrıştırır.

        Returns:
            Ayrıştırılmış ElementTree nesnesi.

        Raises:
            FileNotFoundError: XML dosyası bulunamazsa.
            ET.ParseError: XML sözdizimi hatası varsa.
        """
        if not self.xml_path.exists():
            logger.critical("Nmap XML dosyası bulunamadı: %s", self.xml_path)
            raise NmapParseError(
                f"Nmap XML dosyası bulunamadı: {self.xml_path}"
            )

        logger.info("Nmap XML ayrıştırılıyor: %s", self.xml_path)
        try:
            tree: ET.ElementTree = ET.parse(str(self.xml_path))
            logger.info("XML başarıyla yüklendi.")
            return tree
        except ET.ParseError as exc:
            logger.critical("XML ayrıştırma hatası: %s", exc, exc_info=True)
            raise NmapParseError(
                f"Nmap XML ayrıştırma hatası: {exc}"
            ) from exc

    @staticmethod
    def _extract_service(port_elem: ET.Element) -> ServiceInfo | None:
        """Tek bir <port> elementinden ServiceInfo oluşturur.

        Args:
            port_elem: XML'deki <port> elementi.

        Returns:
            ServiceInfo nesnesi; port kapalıysa veya bilgi yoksa None.
        """
        # Sadece açık portları al
        state_elem: ET.Element | None = port_elem.find("state")
        if state_elem is None:
            return None

        if state_elem.get("state", "").lower() != "open":
            return None

        port_id: int = int(port_elem.get("portid", "0"))
        protocol: str = port_elem.get("protocol", "tcp")

        service_elem: ET.Element | None = port_elem.find("service")
        name: str = ""
        product: str = ""
        version: str = ""
        extrainfo: str = ""
        ostype: str = ""

        if service_elem is not None:
            name = service_elem.get("name", "")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
            extrainfo = service_elem.get("extrainfo", "")
            ostype = service_elem.get("ostype", "")

        info = ServiceInfo(
            port=port_id,
            protocol=protocol,
            name=name,
            product=product,
            version=version,
            extrainfo=extrainfo,
            ostype=ostype
        )

        if not info.query:
            logger.debug(
                "Port %d/%s: servis bilgisi eksik, atlanıyor.", port_id, protocol
            )
            return None

        return info

    # Genel API

    def parse(self) -> list[ServiceInfo]:
        """Nmap XML'ini ayrıştırarak açık portlardaki servisleri döndürür.

        Returns:
            ServiceInfo nesnelerinin listesi.
        """
        tree: ET.ElementTree = self._load_xml()
        root: ET.Element = tree.getroot()

        services: list[ServiceInfo] = []
        host_count: int = 0

        for host in root.findall(".//host"):
            host_count += 1
            # Host adresi log için
            addr_elem: ET.Element | None = host.find("address")
            host_addr: str = (
                addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"
            )

            ports_elem: ET.Element | None = host.find("ports")
            if ports_elem is None:
                logger.debug("Host %s: ports bölümü bulunamadı.", host_addr)
                continue

            for port_elem in ports_elem.findall("port"):
                try:
                    info: ServiceInfo | None = self._extract_service(port_elem)
                    if info is not None:
                        services.append(info)
                        logger.info(
                            "  [+] %s — %d/%s → \"%s\"",
                            host_addr,
                            info.port,
                            info.protocol,
                            info.query,
                        )
                except Exception as exc:
                    logger.error(
                        "Port ayrıştırma hatası (host=%s): %s",
                        host_addr,
                        exc,
                        exc_info=True,
                    )

        logger.info(
            "Nmap taraması tamamlandı: %d host, %d açık servis bulundu.",
            host_count,
            len(services),
        )
        return services

    def get_queries(self) -> list[str]:
        """Servis sorgularını düz string listesi olarak döndürür.

        Returns:
            Aranabilir servis stringlerinin listesi (örn. ["vsftpd 2.3.4", "OpenSSH 7.2"]).
        """
        return [svc.query for svc in self.parse()]


# Doğrudan çalıştırma desteği

def main() -> None:
    """CLI'den doğrudan çağrıldığında çalışır."""
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(name)-24s │ %(levelname)-8s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    if len(sys.argv) < 2:
        print("Kullanım: python nmap_parser.py <nmap_output.xml>")
        sys.exit(1)

    parser = NmapParser(sys.argv[1])
    services: list[ServiceInfo] = parser.parse()

    print(f"\n{'='*60}")
    print(f" Bulunan açık servisler: {len(services)}")
    print(f"{'='*60}")
    for svc in services:
        print(f"  {svc.port}/{svc.protocol:4s}  →  {svc.query}")


if __name__ == "__main__":
    main()
