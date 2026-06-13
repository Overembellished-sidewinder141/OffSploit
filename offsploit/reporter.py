#!/usr/bin/env python3
"""
OffSploit - PDF Reporter Module
===============================
Sızma testi sürecinin sonunda başarılı olan exploit'leri, hedefin
durumunu ve analizleri PDF formatında raporlar.
"""

import logging
from datetime import datetime
from pathlib import Path

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

logger = logging.getLogger("offsploit.reporter")

class OffSploitReporter:
    def __init__(self, target_ip: str, output_dir: str):
        self.target_ip = target_ip
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.filename = self.output_dir / f"OffSploit_Report_{self.target_ip.replace('.', '_')}_{self.report_time}.pdf"

    def _sanitize(self, text: str) -> str:
        """PDF fpdf2 fontu icin Turkce karakterleri ASCII karsiliklarina cevirir."""
        if not text:
            return ""
        replacements = {
            'ç': 'c', 'Ç': 'C',
            'ğ': 'g', 'Ğ': 'G',
            'ı': 'i', 'İ': 'I',
            'ö': 'o', 'Ö': 'O',
            'ş': 's', 'Ş': 'S',
            'ü': 'u', 'Ü': 'U'
        }
        for tr, en in replacements.items():
            text = text.replace(tr, en)
        return text

    def generate_report(self, lhost: str, lport: str, services: list[dict], successful_exploits: list[dict]) -> str:
        """PDF formatında sızma testi sonuç raporu üretir.
        
        Args:
            lhost: Saldırgan IP'si.
            lport: Dinleme portu.
            services: Nmap üzerinden elde edilen açık servisler listesi.
            successful_exploits: Pipeline'dan başarıyla geçen ve uyarlanan exploit'ler.
            
        Returns:
            Oluşturulan PDF dosyasının mutlak yolu. fpdf yüklü değilse None döner.
        """
        if not FPDF:
            logger.error("fpdf2 kütüphanesi bulunamadı! Rapor oluşturulamıyor.")
            return None

        try:
            pdf = FPDF()
            pdf.add_page()

            pdf.set_font("helvetica", "B", 24)
            pdf.set_text_color(180, 0, 0) # Koyu Kırmızı Başlık
            pdf.cell(0, 10, self._sanitize("OffSploit Pentest Raporu"), align="C", new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("helvetica", "I", 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 10, self._sanitize(f"Oluşturulma Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)

            pdf.set_font("helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, self._sanitize("Hedef Bilgileri"), new_x="LMARGIN", new_y="NEXT")
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

            pdf.set_font("helvetica", "", 12)
            pdf.cell(50, 8, self._sanitize("Hedef IP (RHOST):"))
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 8, self.target_ip, new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("helvetica", "", 12)
            pdf.cell(50, 8, self._sanitize("Saldırgan IP (LHOST):"))
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 8, lhost, new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("helvetica", "", 12)
            pdf.cell(50, 8, self._sanitize("Dinleme Portu (LPORT):"))
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 8, lport, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)

            pdf.set_font("helvetica", "B", 14)
            pdf.cell(0, 10, self._sanitize("Açık Servisler (Nmap)"), new_x="LMARGIN", new_y="NEXT")
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

            pdf.set_font("helvetica", "", 10)
            if services:
                # Tablo Başlığı
                pdf.set_fill_color(200, 200, 200)
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(20, 8, "Port", border=1, fill=True)
                pdf.cell(25, 8, "Protokol", border=1, fill=True)
                pdf.cell(145, 8, self._sanitize("Servis / Versiyon"), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

                pdf.set_font("helvetica", "", 10)
                for svc in services:
                    pdf.cell(20, 8, str(svc.get("port")), border=1)
                    pdf.cell(25, 8, str(svc.get("protocol")), border=1)
                    v_str = f"{svc.get('name', '')} {svc.get('product', '')} {svc.get('version', '')}".strip()
                    pdf.cell(145, 8, self._sanitize(v_str), border=1, new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.cell(0, 8, self._sanitize("Açık servis tespit edilemedi."), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)

            pdf.set_font("helvetica", "B", 14)
            pdf.cell(0, 10, self._sanitize("Uyarlanan Exploit'ler"), new_x="LMARGIN", new_y="NEXT")
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)

            if successful_exploits:
                for idx, ex in enumerate(successful_exploits, 1):
                    pdf.set_font("helvetica", "B", 12)
                    pdf.set_text_color(0, 100, 0)
                    pdf.cell(0, 8, self._sanitize(f"{idx}. {ex.get('query')}"), new_x="LMARGIN", new_y="NEXT")

                    pdf.set_font("helvetica", "", 10)
                    pdf.set_text_color(0, 0, 0)
                    pdf.multi_cell(0, 6, self._sanitize(f"Açıklama: {ex.get('description', 'Yok')}"))
                    pdf.cell(0, 6, self._sanitize(f"Tür: {ex.get('type')}  |  Platform: {ex.get('platform')}"), new_x="LMARGIN", new_y="NEXT")
                    pdf.cell(0, 6, self._sanitize(f"Güven Eşiği (Distance): {ex.get('distance')}"), new_x="LMARGIN", new_y="NEXT")

                    c_msg = ex.get('compiler_msg', '')
                    pdf.set_text_color(180, 0, 0) if "hata" in c_msg.lower() or "error" in c_msg.lower() else pdf.set_text_color(0, 0, 180)
                    pdf.multi_cell(0, 6, self._sanitize(f"Derleme/Syntax Durumu: {c_msg}"))
                    pdf.set_text_color(0, 0, 0)

                    # Çıktı yolu
                    pdf.set_font("helvetica", "I", 9)
                    pdf.cell(0, 6, self._sanitize(f"Dosya: {ex.get('output_path')}"), new_x="LMARGIN", new_y="NEXT")
                    pdf.ln(5)
            else:
                pdf.set_font("helvetica", "", 10)
                pdf.cell(0, 8, self._sanitize("Hiçbir exploit başarıyla uyarlanamadı."), new_x="LMARGIN", new_y="NEXT")

            pdf.ln(15)
            pdf.set_font("helvetica", "I", 8)
            pdf.set_text_color(150, 150, 150)
            pdf.cell(0, 10, self._sanitize("Bu rapor OffSploit otonom sızma testi asistanı tarafından üretilmiştir."), align="C")

            # PDF'yi kaydet
            pdf.output(str(self.filename))
            logger.info("PDF raporu oluşturuldu: %s", self.filename)
            return str(self.filename)

        except Exception as e:
            logger.error("PDF oluşturulurken hata: %s", e, exc_info=True)
            return None
