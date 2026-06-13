#!/usr/bin/env python3
"""
OffSploit - Ana Calistirici (CLI Orkestrator)
===============================================
Tum OffSploit modullerini orkestre eden komut satiri arayuzu ve
interaktif shell sistemi.

Kullanim:
    offsploit                                      # Interaktif Mod (TR)
    offsploit -eng                                 # Interaktif Mod (EN)
    offsploit --nmap scan.xml --lhost 10.10.14.5   # Standart CLI Modu
"""

import argparse
import logging
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from offsploit.chromadb_ingest import Ingestor
from offsploit.core_pipeline import OffSploitPipeline
from offsploit.rag_engine import OffSploitRAG

# Console & Global State

console = Console(highlight=False)
logger = logging.getLogger("offsploit.main")

CURRENT_LANG = "tr"

# I18N Dictionaries

I18N: dict[str, dict[str, str]] = {
    "tr": {
        "banner_desc": "Offline Exploit Adaptation Tool v1.0",
        "banner_sub": "RAG + Local LLM Destekli Sızma Testi Aracı",
        "step_1": "Adım 1/4 \u2014 Nmap Keşif Verileri Analiz Ediliyor...",
        "nmap_not_found": "Nmap dosyası bulunamadı:",
        "nmap_error": "Nmap ayrıştırma (parse) hatası:",
        "no_services": "Hedefte hiçbir açık servis bulunamadı. İşlem iptal ediliyor.",
        "services_found": "Hedefte istismar edilebilir [bold]{count}[/bold] adet açık servis bulundu:",
        "col_port": "Açık Port",
        "col_service": "Servis Türü",
        "step_2": "Adım 2/4 \u2014 ChromaDB Üzerinde Semantik Exploit Taraması Yapılıyor...",
        "rag_error": "Veritabanı (RAG) arama hatası:",
        "no_exploit": "Hedef sistem için kaynak koduna sahip uygun bir exploit eşleşmesi bulunamadı.",
        "match_found": "Tespit edilen servis için bulunan en iyi exploit:",
        "desc": "Zafiyet (Exploit) Açıklaması",
        "file": "Dosya",
        "platform": "Hedef Platform",
        "type": "Exploit Türü",
        "distance": "Eşleşme Oranı (Mesafe)",
        "source": "Kaynak",
        "chars": "karakter",
        "step_3": "Adım 3/4 \u2014 LLM (Ollama) Üzerinden Exploit Uyarlaması Başlatıldı...",
        "skip_llm": "Hedef IP (RHOST) ve Saldırgan IP (LHOST) belirtilmedi. LLM adaptasyonu atlanıyor.",
        "ollama_unreachable": "Ollama sunucusuna ulaşılamadı:",
        "ollama_hint": "Lütfen yerel ağınızda Ollama'nın çalıştığından emin olun (Örn: ollama serve).",
        "model": "Kullanılan Model",
        "processing_llm": "LLM kod adaptasyonunu gerçekleştiriyor...",
        "llm_empty": "LLM motorundan boş yanıt döndü. Exploit'in orijinal kaynak kodu kullanılacak.",
        "llm_done": "LLM uyarlama işlemi başarıyla tamamlandı ({count} karakter).",
        "ollama_conn_err": "Ollama bağlantı hatası:",
        "llm_adapt_err": "LLM kod uyarlama hatası:",
        "step_4": "Adım 4/4 \u2014 İstismar Kodları (Payload) ve Rapor Kaydediliyor...",
        "exploit_saved": "Uyarlanan exploit başarıyla kaydedildi:",
        "save_err": "Dosya yazma hatası:",
        "summary": "OffSploit İşlemi Başarıyla Tamamlandı",
        "key": "Parametre",
        "value": "Detay",
        "target_service": "Hedef Servis",
        "output_file": "Çıktı Dosyası",
        "need_action": "Geçerli bir argüman bulunamadı. Lütfen --scan parametresi verin veya parametresiz çalıştırıp interaktif kabuğu başlatın.",
        "shell_welcome": "OffSploit İnteraktif Kabuğuna (Shell) Hoş Geldiniz! Kullanılabilir komutları görmek için 'help' yazın.",
        "shell_exit": "OffSploit oturumu sonlandırılıyor...",
        "shell_help": (
            "[bold cyan]Kullanılabilir Komutlar:[/bold cyan]\n"
            "  [bold]set <değişken> <değer>[/bold] - Hedef parametrelerini (rhost, lhost, nmap, model vb.) tanımlar.\n"
            "  [bold]options[/bold]               - Aktif konfigürasyonu ve mevcut ayarları görüntüler.\n"
            "  [bold]run / exploit[/bold]           - Nmap analizi, RAG exploit tespiti ve LLM uyarlama zincirini başlatır.\n"
            "  [bold]search <sorgu>[/bold]          - Veritabanında spesifik bir zafiyet araması yapar (Örn: search vsftpd 2.3.4).\n"
            "  [bold]update-db[/bold]               - Exploit-DB CSV dosyasını vektörize ederek yerel ChromaDB veritabanını günceller.\n"
            "  [bold]chat <mesaj>[/bold]           - Hedefe sızdıktan sonra yetki yükseltme tavsiyeleri için LLM Danışmanı ile konuşur.\n"
            "  [bold]load-bh <klasor>[/bold]        - Active Directory BloodHound JSON verilerini yükleyip analiz grafını oluşturur.\n"
            "  [bold]ad-path <bas> <bitis>[/bold]  - İki AD düğümü arasındaki en kısa Attack Path'i bulup LLM ile sömürü adımlarını çıkarır.\n"
            "  [bold]lang <tr/en>[/bold]            - Arayüz dilini değiştirir (Varsayılan TR).\n"
            "  [bold]clear[/bold]                   - Konsol ekranını temizler.\n"
            "  [bold]exit / quit[/bold]             - Oturumu sonlandırır."
        ),
        "shell_options": "[bold cyan]Mevcut Yapılandırma (Options):[/bold cyan]",
        "chat_no_msg": "Lütfen Post-Exploit danışmanına durumunuzu veya sorunuzu belirtin (Örn: chat www-data kullanıcısındayım, kernel 3.13.0, nasıl root olurum?)",
        "chat_title": "OffSploit Sızma Sonrası Danışmanı",
        "search_no_query": "Arama yapmak için bir sorgu girmelisiniz (Örn: search apache).",
        "set_no_args": "Bir değişken ve değer girmelisiniz (Örn: set lport 4444).",
        "invalid_var": "Geçersiz yapılandırma değişkeni:",
        "set_success": "[bold cyan]{var}[/bold cyan] parametresi [bold green]{val}[/bold green] olarak yapılandırıldı.",
        "db_update_start": "ChromaDB veritabanı indeksleniyor (Lütfen bekleyin)...",
        "ingest_start": "Exploit-DB verileri aktarılıyor...",
        "processing": "İşleniyor",
        "db_update_done": "İşlem Tamamlandı. Toplam [bold]{count}[/bold] adet exploit ChromaDB'ye aktarıldı.",
        "search_title": "Arama Sonuçları",
        "score": "Doğruluk Skoru",
    },
    "en": {
        "banner_desc": "Offline Exploit Adaptation Tool v1.0",
        "banner_sub": "RAG + Local LLM Powered Penetration Testing Tool",
        "step_1": "Step 1/4 \u2014 Parsing Nmap XML...",
        "nmap_not_found": "Nmap file not found:",
        "nmap_error": "Nmap parse error:",
        "no_services": "No open services found. Exiting.",
        "services_found": "[bold]{count}[/bold] open services found:",
        "col_port": "Port",
        "col_service": "Service",
        "step_2": "Step 2/4 \u2014 Searching exploit in ChromaDB...",
        "rag_error": "RAG search error:",
        "no_exploit": "No suitable exploit with source code found.",
        "match_found": "Best match found:",
        "desc": "Description",
        "file": "File",
        "platform": "Platform",
        "type": "Type",
        "distance": "Distance",
        "source": "Source",
        "chars": "chars",
        "step_3": "Step 3/4 \u2014 Adapting exploit via Ollama LLM...",
        "skip_llm": "LHOST and RHOST not provided. Skipping LLM adaptation.",
        "ollama_unreachable": "Ollama server unreachable:",
        "ollama_hint": "Ensure Ollama is running: ollama serve",
        "model": "Model",
        "processing_llm": "Processing via LLM...",
        "llm_empty": "LLM returned empty response. Using original code.",
        "llm_done": "LLM adaptation complete ({count} chars).",
        "ollama_conn_err": "Ollama connection error:",
        "llm_adapt_err": "LLM adaptation error:",
        "step_4": "Step 4/4 \u2014 Saving adapted exploit...",
        "exploit_saved": "Exploit saved to:",
        "save_err": "File save error:",
        "summary": "OffSploit Summary",
        "key": "Key",
        "value": "Value",
        "target_service": "Target Service",
        "output_file": "Output File",
        "need_action": "You must specify an action: provide --nmap or run in interactive mode",
        "shell_welcome": "Welcome to OffSploit Interactive Shell! Type 'help' for commands.",
        "shell_exit": "Exiting...",
        "shell_help": (
            "[bold cyan]Available Commands:[/bold cyan]\n"
            "  [bold]set <variable> <value>[/bold] - Define target parameters (e.g., rhost, lhost, nmap, model).\n"
            "  [bold]options[/bold]               - Display the active configuration and current settings.\n"
            "  [bold]run / exploit[/bold]           - Start the Nmap analysis, RAG exploit detection, and LLM adaptation pipeline.\n"
            "  [bold]search <query>[/bold]          - Perform semantic exploit search in the database (e.g., search vsftpd 2.3.4).\n"
            "  [bold]update-db[/bold]               - Update the local ChromaDB vector database from the Exploit-DB CSV file.\n"
            "  [bold]chat <message>[/bold]         - Consult the LLM for Post-Exploitation advice based on target system findings.\n"
            "  [bold]load-bh <folder>[/bold]       - Load BloodHound JSON files to build the Active Directory graph.\n"
            "  [bold]ad-path <src> <dest>[/bold]   - Find Attack Path between AD nodes and generate exploitation plan via LLM.\n"
            "  [bold]lang <tr/en>[/bold]            - Change the interface language.\n"
            "  [bold]clear[/bold]                   - Clear the console screen.\n"
            "  [bold]exit / quit[/bold]             - Terminate the session."
        ),
        "shell_options": "[bold cyan]Current Configuration (Options):[/bold cyan]",
        "chat_no_msg": "Please specify your situation or question for the Post-Exploit Advisor (e.g., chat I have a www-data shell on kernel 3.13.0, how to root?)",
        "chat_title": "OffSploit Post-Exploitation Advisor",
        "search_no_query": "Please enter a search term. (Example: search vsftpd)",
        "set_no_args": "Please provide a variable and a value. (Example: set rhost 10.10.10.3)",
        "invalid_var": "Invalid variable:",
        "set_success": "[bold cyan]{var}[/bold cyan] is set to [bold green]{val}[/bold green].",
        "db_update_start": "Updating ChromaDB database...",
        "ingest_start": "Ingest starting...",
        "processing": "Processing",
        "db_update_done": "Successfully ingested [bold]{count}[/bold] exploits into ChromaDB.",
        "search_title": "Search Results",
        "score": "Score",
    }
}

def t(key: str, **kwargs) -> str:
    """I18N cevirisini dondurur."""
    text = I18N.get(CURRENT_LANG, I18N["tr"]).get(key, key)
    if kwargs:
        text = text.format(**kwargs)
    return text

# ASCII Arts

BANNERS: list[str] = [
    # 1. Slant Style (Aggressive)
    r"""[bold red]
   ____  _____________       __      _ __ 
  / __ \/ __/ __/ ___/____  / /___  (_) /_
 / / / / /_/ /_ \__ \/ __ \/ / __ \/ / __/
/ /_/ / __/ __/___/ / /_/ / / /_/ / / /_  
\____/_/ /_/  /____/ .___/_/\____/_/\__/  
                  /_/                     
[/bold red]""",

    # 2. Graffiti Style (Hacker)
    r"""[bold magenta]
________   _____  _____  _________      .__         .__  __   
\_____  \_/ ____\/ ____\/   _____/_____ |  |   ____ |__|/  |_ 
 /   |   \   __\\   __\ \_____  \\____ \|  |  /  _ \|  \   __\
/    |    \  |   |  |   /        \  |_> >  |_(  <_> )  ||  |  
\_______  /__|   |__|  /_______  /   __/|____/\____/|__||__|  
        \/                     \/|__|                         
[/bold magenta]""",

    # 3. Standard Style (Clean but bold)
    r"""[bold cyan]
  ___   __  __ ____        _       _ _   
 / _ \ / _|/ _/ ___| _ __ | | ___ (_) |_ 
| | | | |_| |_\___ \| '_ \| |/ _ \| | __|
| |_| |  _|  _|___) | |_) | | (_) | | |_ 
 \___/|_| |_| |____/| .__/|_|\___/|_|\__|
                    |_|                  
[/bold cyan]""",

    # 4. Doom Style (Thick)
    r"""[bold yellow]
 _____  __  __ _____       _       _ _   
|  _  |/ _|/ _/  ___|     | |     (_) |  
| | | | |_| |_\ `--. _ __ | | ___  _| |_ 
| | | |  _|  _|`--. \ '_ \| |/ _ \| | __|
\ \_/ / | | | /\__/ / |_) | | (_) | | |_ 
 \___/|_| |_| \____/| .__/|_|\___/|_|\__|
                    | |                  
                    |_|                  
[/bold yellow]""",
]


def show_banner() -> None:
    """Rastgele bir banner secer ve gosterir."""
    console.print()
    console.print(random.choice(BANNERS))
    console.print("[dim italic]          Author: Egnake[/dim italic]\n")
    console.print(
        Panel.fit(
            f"[bold white]{t('banner_desc')}[/]\n"
            f"[dim]{t('banner_sub')}[/dim]",
            border_style="bright_cyan",
            padding=(0, 2),
        )
    )
    console.print()


# Yardimci cikti fonksiyonlari

def step(msg: str) -> None:
    console.print(f"\n[bold cyan][\u25b6][/bold cyan] {msg}")

def success(msg: str) -> None:
    console.print(f"[bold green][\u2713][/bold green] {msg}")

def warning(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")

def error(msg: str) -> None:
    console.print(f"[bold red][\u2717][/bold red] {msg}")

def info(msg: str) -> None:
    console.print(f"  [dim cyan]\u2502[/dim cyan] {msg}")

def detect_extension(file_path: str) -> str:
    suffix: str = Path(file_path).suffix.lower()
    ext_map: dict[str, str] = {
        ".c": ".c", ".cpp": ".c", ".h": ".c",
        ".py": ".py", ".py2": ".py", ".py3": ".py",
        ".rb": ".rb", ".pl": ".pl", ".sh": ".sh", ".java": ".java",
    }
    return ext_map.get(suffix, ".txt")

def save_output(content: str, extension: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file: Path = output_dir / f"adapted_exploit{extension}"
    counter: int = 1
    while output_file.exists():
        output_file = output_dir / f"adapted_exploit_{counter}{extension}"
        counter += 1
    output_file.write_text(content, encoding="utf-8")
    return output_file

# Pipeline & Veritabani

def run_nmap_scan(target: str, extra_args: str = "-sV -p-") -> Path:
    """Nmap'i calistirip XML ciktisini dondurur."""
    step(f"Nmap taramasi baslatiliyor: {target} (Bu islem uzun surebilir...)")
    xml_path = Path(tempfile.mkdtemp()) / "scan.xml"

    cmd = ["nmap"] + extra_args.split() + [target, "-oX", str(xml_path)]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        success(f"Nmap taramasi tamamlandi. Cikti: {xml_path}")
        return xml_path
    except FileNotFoundError:
        error("Nmap bulunamadi! Lutfen sisteminizde Nmap'in kurulu ve PATH'e ekli oldugundan emin olun.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        error(f"Nmap taramasi basarisiz oldu: {e.stderr.decode('utf-8', errors='ignore')}")
        sys.exit(1)

def run_update_db(args: argparse.Namespace) -> None:
    step(t("db_update_start"))
    try:
        with Progress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[bold]{task.description}[/bold]"),
            BarColumn(bar_width=40, complete_style="cyan", finished_style="green"),
            TextColumn("[bold cyan]{task.percentage:>3.0f}%[/bold cyan]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(t("ingest_start"), total=None)

            def on_progress(current: int, total: int, msg: str) -> None:
                progress.update(
                    task, completed=current, total=total,
                    description=f"{t('processing')} ({current}/{total})"
                )

            ingestor = Ingestor(
                csv_path=args.csv, db_path=args.db_path, progress_callback=on_progress,
            )
            count: int = ingestor.ingest()

        success(t("db_update_done", count=count))

    except FileNotFoundError as exc:
        error(f"CSV error: {exc}")
    except Exception as exc:
        error(f"DB Error: {exc}")
        logger.critical("DB Error:", exc_info=True)


def run_exploit_pipeline(args: argparse.Namespace) -> None:
    config = vars(args).copy()
    config["chromadb_path"] = args.db_path
    config["ollama_timeout"] = 300

    output_path = ""
    target_query = ""
    best_match_desc = ""
    platform = ""

    def on_event(event_type: str, data: dict):
        nonlocal output_path, target_query, best_match_desc, platform

        if event_type == "step_start":
            step_num = data.get('step')
            if step_num == 1: step(t("step_1"))
            elif step_num == 1.5: step("Adim 1.5/4 \u2014 Pre-Flight Check...")
            elif step_num == 2: step(t("step_2"))
            elif step_num == 3: step(t("step_3"))
            elif step_num == 3.5: step("Adim 3.5/4 \u2014 Compiler Check (Self-Healing)...")
            elif step_num == 3.7: step("Adim 3.7/4 \u2014 Ghost Mode (OPSEC Engine)...")
            elif step_num == 3.8: step("Adim 3.8/4 \u2014 Obfuscation (EDR/AV Bypass)...")
            elif step_num == 3.9: step("Adim 3.9/4 \u2014 Fileless (In-Memory Wrapper)...")
            elif step_num == 4: step(t("step_4"))

        elif event_type == "step_done":
            step_num = data.get('step')
            if step_num == 1:
                services = data.get('data', [])
                success(t("services_found", count=len(services)))
                table = Table(box=box.ROUNDED, border_style="dim cyan", show_header=True, header_style="bold cyan")
                table.add_column(t("col_port"), style="bold white", width=12)
                table.add_column(t("col_service"), style="white")
                for svc in services:
                    table.add_row(f"{svc['port']}/{svc['protocol']}", svc['query'])
                console.print(table)
            elif step_num == 1.5:
                success(f"Hedef erisilebilir: {data.get('data', {}).get('message', '')}")
            elif step_num == 2:
                success(t("match_found"))
                match_data = data.get('data', {})
                target_query = match_data.get('query', '')
                best_match_desc = match_data.get('description', '')[:60]
                platform = match_data.get('platform', '')

                info(f"[bold]{t('desc')} :[/bold] {match_data.get('description', '')[:80]}")
                info(f"[bold]{t('target_service')} :[/bold] {match_data.get('query', '')}")
                info(f"[bold]{t('file')} :[/bold] [dim]{match_data.get('file_path', '')}[/dim]")
                info(f"[bold]{t('platform')} :[/bold] {match_data.get('platform', '')}")
                info(f"[bold]{t('type')} :[/bold] {match_data.get('type', '')}")
                info(f"[bold]{t('distance')} :[/bold] {match_data.get('distance', 0)}")
                info(f"[bold]{t('source')} :[/bold] {match_data.get('source_length', 0)} {t('chars')}")
            elif step_num == 3:
                success(t("llm_done", count=data.get('data', {}).get('length', 0)))
            elif step_num == 3.5:
                msg = data.get('data', {}).get('message', '')
                if "Atlandi" in msg or "atlanildi" in msg.lower():
                    info(msg)
                else:
                    success(msg)
            elif step_num in [3.7, 3.8, 3.9]:
                msg = data.get('data', {}).get('message', '')
                if "atlan" in msg.lower() or "skipped" in msg.lower():
                    info(msg)
                else:
                    success(msg)
            elif step_num == 4:
                report_path = data.get('data', {}).get('path', '')
                if report_path:
                    success(f"Rapor olusturuldu: [bold]{report_path}[/bold]")

        elif event_type == "step_warning" or event_type == "step_progress":
            warning(data.get("message", ""))
        elif event_type == "error":
            error(data.get("message", ""))
        elif event_type == "complete":
            if data.get("success"):
                exploits = data.get("exploits", [])
                report = data.get("report_path", "")

                console.print("\n")
                summary_table = Table(
                    box=box.HEAVY_EDGE, border_style="bright_cyan", show_header=True, padding=(0, 1),
                    title=f"[bold green]\u2713 {t('summary')} ({len(exploits)} Servis)[/bold green]", title_style="bold",
                )
                summary_table.add_column("Servis (Query)", style="cyan")
                summary_table.add_column("Secilen Exploit", style="white")
                summary_table.add_column("Cikti Dosyasi", style="green")

                for exp in exploits:
                    summary_table.add_row(exp["query"], exp["description"][:50] + "...", Path(exp["output_path"]).name)

                console.print(summary_table)
                if report:
                    console.print(f"\n[bold cyan]Tam Rapor:[/] [underline]{report}[/underline]\n")
            else:
                error(data.get("message", "Bilinmeyen bir hata olustu."))

    pipeline = OffSploitPipeline(config, on_event)
    pipeline.run(
        nmap_path=args.nmap,
        lhost=args.lhost,
        rhost=args.rhost,
        lport=args.lport,
        model=args.model,
        top_k=args.top_k,
        obfuscate=args.obfuscate,
        fileless=args.fileless,
        ghost=args.ghost
    )


# Interactive Shell Mode

def start_interactive_shell(initial_state: dict) -> None:
    """Metasploit benzeri interaktif prompt baslatir."""
    state = initial_state.copy()

    console.print(f"[bold cyan]{t('shell_welcome')}[/bold cyan]\n")

    while True:
        try:
            cmd_line = console.input("[bold red]OffSploit[/bold red] > ").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split()
            cmd = parts[0].lower()

            if cmd in ["exit", "quit"]:
                console.print(f"[dim]{t('shell_exit')}[/dim]")
                break

            elif cmd == "help":
                console.print(f"\n{t('shell_help')}\n")

            elif cmd == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')

            elif cmd == "lang":
                global CURRENT_LANG
                if len(parts) > 1 and parts[1].lower() in ["tr", "en", "eng"]:
                    CURRENT_LANG = "en" if parts[1].lower() in ["en", "eng"] else "tr"
                    console.print(f"[bold green]Language set to: {CURRENT_LANG.upper()}[/bold green]")
                else:
                    console.print("[bold yellow]Usage: lang tr | lang en[/bold yellow]")

            elif cmd == "options":
                table = Table(box=box.MINIMAL_DOUBLE_HEAD, header_style="bold cyan")
                table.add_column(t("key").upper(), style="bold white")
                table.add_column(t("value").upper(), style="cyan")
                for k in ["scan", "nmap", "lhost", "rhost", "lport", "llm_provider", "api_key", "model", "top_k", "db_path", "csv", "obfuscate", "ghost", "fileless"]:
                    table.add_row(k.upper(), str(state.get(k, "")))
                console.print()
                console.print(table)
                console.print()

            elif cmd == "set":
                if len(parts) < 3:
                    console.print(f"[bold yellow]{t('set_no_args')}[/bold yellow]")
                else:
                    var = parts[1].lower()
                    val = " ".join(parts[2:])
                    if var in state:
                        # Try int conversion for numeric fields
                        if var == "top_k":
                            try: val = int(val)
                            except: pass
                        elif var in ["obfuscate", "ghost", "fileless"]:
                            val = str(val).lower() in ["true", "1", "yes", "y"]
                        state[var] = val
                        console.print(t("set_success", var=var.upper(), val=val))
                    else:
                        console.print(f"[bold red]{t('invalid_var')} {var}[/bold red]")

            elif cmd in ["run", "exploit"]:
                if state.get("scan"):
                    # Nmap taramasini canli yap
                    if not state.get("rhost"):
                        state["rhost"] = state.get("scan")
                    xml_path = run_nmap_scan(state["scan"])
                    state["nmap"] = str(xml_path)
                elif not state.get("nmap"):
                    console.print("[bold red]HATA:[/] Lutfen 'nmap' XML dosyasi (set nmap <dosya>) veya canli tarama (set scan 192.168.1.x) belirtin.")
                    continue

                args_obj = argparse.Namespace(**state)
                run_exploit_pipeline(args_obj)

            elif cmd == "update-db":
                args_obj = argparse.Namespace(**state)
                run_update_db(args_obj)

            elif cmd == "search":
                if len(parts) < 2:
                    console.print(f"[bold yellow]{t('search_no_query')}[/bold yellow]")
                else:
                    query = " ".join(parts[1:])
                    try:
                        rag = OffSploitRAG(db_path=state["db_path"], exploitdb_root=state["exploitdb_root"], top_k=int(state["top_k"]))
                        matches = rag.search(query, top_k=5)
                        if not matches:
                            console.print(f"[yellow]{t('no_exploit')}[/yellow]")
                        else:
                            table = Table(title=t("search_title"), box=box.SIMPLE)
                            table.add_column(t("score"), justify="right", style="cyan")
                            table.add_column("ID", style="magenta")
                            table.add_column(t("desc"))
                            table.add_column(t("platform"))
                            for m in matches:
                                score = f"{(1 - m.distance):.2f}"
                                table.add_row(score, str(m.exploit_id), m.description[:50], m.platform)
                            console.print(table)
                    except Exception as e:
                        console.print(f"[bold red]HATA:[/] {e}")

            elif cmd in ["chat", "post"]:
                if len(parts) < 2:
                    console.print(f"[bold yellow]{t('chat_no_msg')}[/bold yellow]")
                else:
                    user_msg = " ".join(parts[1:])
                    # Spin a loader while waiting for LLM
                    with Progress(SpinnerColumn(), TextColumn("[cyan]LLM düşünülüyor...[/cyan]"), transient=True) as progress:
                        progress.add_task("chatting")
                        from offsploit.llm_client import LLMClient
                        client = LLMClient(
                            provider=state.get("llm_provider", "ollama"),
                            ollama_url=state.get("ollama_url", "http://localhost:11434"),
                            ollama_model=state.get("model", "qwen2.5-coder:14b"),
                            api_key=state.get("api_key", "")
                        )
                        answer = client.ask_post_exploitation(user_msg)

                    from rich.markdown import Markdown
                    from rich.panel import Panel
                    console.print(Panel(
                        Markdown(answer),
                        title=f"[bold green]{t('chat_title')}[/bold green]",
                        border_style="green",
                        box=box.ROUNDED
                    ))

            elif cmd == "load-bh":
                if len(parts) < 2:
                    console.print("[bold yellow]Kullanım: load-bh <klasor_yolu>[/bold yellow]")
                else:
                    folder_path = " ".join(parts[1:])
                    from offsploit.bloodhound_parser import BloodHoundParser
                    bh_parser = BloodHoundParser()
                    with Progress(SpinnerColumn(), TextColumn("[cyan]BloodHound verileri okunuyor...[/cyan]"), transient=True) as progress:
                        progress.add_task("bh")
                        success = bh_parser.load_directory(folder_path)

                    if success:
                        state["bh_parser"] = bh_parser
                        console.print(f"[bold green]BloodHound grafı başarıyla oluşturuldu! ({bh_parser.graph.number_of_nodes()} düğüm)[/bold green]")
                    else:
                        console.print("[bold red]BloodHound verileri yüklenemedi. Klasör yolunu kontrol edin.[/bold red]")

            elif cmd == "ad-path":
                if len(parts) < 3:
                    console.print("[bold yellow]Kullanım: ad-path <baslangic_dugumu> <hedef_dugum>[/bold yellow]")
                else:
                    bh_parser = state.get("bh_parser")
                    if not bh_parser:
                        console.print("[bold red]HATA:[/] Önce 'load-bh <klasor>' ile BloodHound verilerini yükleyin.")
                        continue

                    start_node = parts[1]
                    end_node = parts[2]

                    path_details = bh_parser.find_attack_path(start_node, end_node)
                    if not path_details:
                        console.print("[bold yellow]Saldırı yolu bulunamadı veya düğümler eksik.[/bold yellow]")
                        continue

                    path_str = bh_parser.format_path_for_llm(path_details)
                    console.print(f"\n[bold cyan]Saldırı Yolu Bulundu:[/bold cyan]\n{path_str}\n")

                    with Progress(SpinnerColumn(), TextColumn("[cyan]LLM üzerinden AD Exploitation adımları çıkarılıyor...[/cyan]"), transient=True) as progress:
                        progress.add_task("ad_llm")
                        from offsploit.llm_client import LLMClient
                        client = LLMClient(
                            provider=state.get("llm_provider", "ollama"),
                            ollama_url=state.get("ollama_url", "http://localhost:11434"),
                            ollama_model=state.get("model", "qwen2.5-coder:14b"),
                            api_key=state.get("api_key", "")
                        )
                        answer = client.ask_ad_exploiter(path_str)

                    from rich.markdown import Markdown
                    from rich.panel import Panel
                    console.print(Panel(
                        Markdown(answer),
                        title="[bold green]AD Exploiter Planı[/bold green]",
                        border_style="green",
                        box=box.ROUNDED
                    ))

            else:
                console.print(f"[dim]Bilinmeyen komut: {cmd}. Yardim icin 'help' yazin.[/dim]")

        except KeyboardInterrupt:
            console.print(f"\n[dim]{t('shell_exit')}[/dim]")
            break
        except EOFError:
            break


# Main Entry Point

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="offsploit",
        description="OffSploit \u2014 Offline Exploit Adaptation Tool",
    )
    parser.add_argument("--scan", type=str, default="", help="Otomatik Nmap taraması başlatılacak hedef IP veya Subnet (Örn: 192.168.1.10).")
    parser.add_argument("--nmap", type=str, default="", help="Analiz edilecek mevcut Nmap XML çıktı dosyasının yolu.")
    parser.add_argument("--lhost", type=str, default="", help="Saldırgan sistemin IP adresi (Local Host / LHOST). Örn: VPN tünel ip'si.")
    parser.add_argument("--rhost", type=str, default="", help="Hedef sistemin IP adresi (Remote Host / RHOST). --scan kullanılıyorsa gereksizdir.")
    parser.add_argument("--lport", type=str, default="4444", help="Saldırgan sistemde dinlemeye alınacak port (Local Port / LPORT). Varsayılan: 4444")
    parser.add_argument("--llm-provider", type=str, default="ollama", help="Kullanılacak LLM sağlayıcısı (ollama, gemini, openai).")
    parser.add_argument("--api-key", type=str, default="", help="Gemini veya OpenAI için API anahtarı.")
    parser.add_argument("--model", type=str, default="qwen2.5-coder:14b", help="Kod adaptasyonunda kullanılacak LLM modeli.")
    parser.add_argument("--top-k", type=int, default=1, help="RAG aramasında getirilecek maksimum exploit sayısı (Varsayılan: 1).")
    parser.add_argument("--update-db", action="store_true", help="Exploit-DB CSV dosyasını okuyarak ChromaDB veritabanını günceller veya sıfırdan kurar.")
    parser.add_argument("--csv", type=str, default="exploitdb/files_exploits.csv", help="Exploit-DB arşivi CSV dosyasının dosya yolu.")
    parser.add_argument("--exploitdb-root", type=str, default="exploitdb", help="Exploit-DB kaynak kodlarının bulunduğu kök dizin.")
    parser.add_argument("--db-path", type=str, default="./offsploit_chromadb", help="Vektör veritabanının (ChromaDB) depolanacağı dizin.")
    parser.add_argument("--output-dir", type=str, default="./output", help="Raporların ve uyarlanan istismar kodlarının kaydedileceği dizin.")
    parser.add_argument("--ollama-url", type=str, default="http://localhost:11434", help="Ollama API servisinin adresi.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı hata ayıklama (DEBUG) çıktılarını konsola yazdırır.")
    parser.add_argument("--skip-preflight", action="store_true", help="İşleme başlamadan önce hedefin erişilebilir (UP) olup olmadığını denetleyen port testini atlar.")
    parser.add_argument("-eng", "--english", action="store_true", help="Arayüzü ve çıktı mesajlarını İngilizce diliyle başlatır.")
    parser.add_argument("--obfuscate", action="store_true", help="Oluşturulan kodda Gelişmiş EDR/AV Bypass (Anti-Debug, Sandbox Evasion, vb.) tekniklerini uygular.")
    parser.add_argument("--fileless", action="store_true", help="Exploit'i diske dokunmadan bellek-içi (In-Memory Execution) çalışacak bir sarmalayıcıya gömer.")
    parser.add_argument("--ghost", action="store_true", help="Ghost Mode (OPSEC): Exploit çalıştığında kendi izlerini silmesini (Self-Delete, Log Clear, Masking) sağlar.")
    return parser


def main() -> None:
    global CURRENT_LANG

    # Windows icin UTF-8 encoding
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    arg_parser = build_parser()

    # Eger arguman yoksa veya sadece dille ilgili argumanlar varsa, interactive moda gec
    interactive_mode = False
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ["-eng", "--english"]):
        interactive_mode = True

    args = arg_parser.parse_args()

    if getattr(args, 'english', False):
        CURRENT_LANG = "en"

    # Rich-based logging
    log_level = logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(name)s | %(message)s", datefmt="%H:%M:%S",
        handlers=[RichHandler(console=console, show_time=True, show_path=False, markup=True)]
    )

    show_banner()

    if interactive_mode:
        start_interactive_shell(vars(args))
    else:
        if getattr(args, 'update_db', False):
            run_update_db(args)
        elif getattr(args, 'scan', ""):
            if not getattr(args, 'rhost', ""):
                args.rhost = args.scan
            xml_path = run_nmap_scan(args.scan)
            args.nmap = str(xml_path)
            run_exploit_pipeline(args)
        elif getattr(args, 'nmap', ""):
            run_exploit_pipeline(args)
        else:
            error(t("need_action"))
            console.print()
            arg_parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
