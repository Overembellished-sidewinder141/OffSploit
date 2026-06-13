#!/usr/bin/env python3
"""
OffSploit - LLM Client Factory
==============================
Provides a unified interface for Ollama, Google Gemini, and OpenAI.
"""

import json
import logging
from pathlib import Path

import requests

from offsploit.response_parser import extract_code_from_response

logger = logging.getLogger("offsploit.llm")


class LLMProviderInterface:
    def health_check(self) -> bool: pass
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1, max_tokens: int = 4096) -> str: pass

class OllamaProvider(LLMProviderInterface):
    def __init__(self, base_url: str, model: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def health_check(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if resp.status_code == 200:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                logger.info("Ollama erişilebilir. Yüklü modeller: %s", models)
                return True
            return False
        except Exception:
            return False

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1, max_tokens: int = 4096) -> str:
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        api_url = f"{self.base_url}/api/generate"
        try:
            resp = requests.post(api_url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            raise

class GeminiProvider(LLMProviderInterface):
    def __init__(self, api_key: str, model: str = "gemini-1.5-pro"):
        self.api_key = api_key
        self.model = model
        try:
            import google.generativeai as genai
            if self.api_key:
                genai.configure(api_key=self.api_key)
            self.genai = genai
        except ImportError:
            logger.error("google-generativeai module is not installed.")
            self.genai = None

    def health_check(self) -> bool:
        if not self.genai or not self.api_key: return False
        return True # Simplified

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1, max_tokens: int = 4096) -> str:
        if not self.genai: raise RuntimeError("Gemini library not installed.")
        model = self.genai.GenerativeModel(self.model, system_instruction=system_prompt)
        response = model.generate_content(
            user_prompt,
            generation_config=self.genai.types.GenerationConfig(temperature=temperature, max_output_tokens=max_tokens)
        )
        return response.text.strip()

class OpenAIProvider(LLMProviderInterface):
    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model
        try:
            import openai
            self.client = openai.OpenAI(api_key=self.api_key) if self.api_key else None
        except ImportError:
            logger.error("openai module is not installed.")
            self.client = None

    def health_check(self) -> bool:
        return self.client

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1, max_tokens: int = 4096) -> str:
        if not self.client: raise RuntimeError("OpenAI library not installed.")
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens
        )
        return response.choices[0].message.content.strip()


class LLMClient:
    """Yapay zeka modellerine erisim saglayan ana istemci (Factory Pattern)."""

    def __init__(self, provider: str = "ollama", **kwargs):
        self.provider_name = provider.lower()
        self.prompts = {}
        prompts_path = Path(__file__).parent / "prompts.json"
        if prompts_path.exists():
            try:
                self.prompts = json.loads(prompts_path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.error("prompts.json okunamadı: %s", e)

        if self.provider_name == "ollama":
            self.provider = OllamaProvider(
                base_url=kwargs.get("ollama_url", "http://localhost:11434"),
                model=kwargs.get("ollama_model", "qwen2.5-coder:14b"),
                timeout=kwargs.get("ollama_timeout", 300)
            )
        elif self.provider_name == "gemini":
            m = kwargs.get("ollama_model", "gemini-1.5-pro")
            if "gemini" not in m: m = "gemini-1.5-pro"
            self.provider = GeminiProvider(api_key=kwargs.get("api_key", ""), model=m)
        elif self.provider_name == "openai":
            m = kwargs.get("ollama_model", "gpt-4o")
            if "gpt" not in m: m = "gpt-4o"
            self.provider = OpenAIProvider(api_key=kwargs.get("api_key", ""), model=m)
        else:
            raise ValueError(f"Desteklenmeyen LLM Provider: {self.provider_name}")

    def health_check(self) -> bool:
        return self.provider.health_check()

    def _build_system_prompt(self, lhost: str, rhost: str, lport: str) -> str:
        template = self.prompts.get("ollama_client", {}).get(
            "system_prompt",
            "Sen 'OffSploit' adında profesyonel bir siber güvenlik ve sızma testi asistanısın. "
            "Görevin, aşağıda verilen ham Exploit-DB kaynak kodunu alıp hedef ağ parametrelerine göre otonom olarak uyarlamaktır. "
            "Lütfen kullanıcının sağladığı LHOST={lhost}, RHOST={rhost} ve LPORT={lport} "
            "değerlerini koddaki ilgili değişkenlere kusursuzca yerleştir. "
            "Sadece güncellenmiş, derlenmeye ve çalıştırılmaya hazır tam kaynak kodunu ver. "
            "ÖNEMLİ: Kodun en altına, yorum satırları içerisinde veya Markdown (```) bloğu kullanarak, "
            "bu exploit'in Linux veya Windows ortamında nasıl derleneceğini (örn: gcc komutları) "
            "ve tam olarak nasıl çalıştırılacağını (Kullanım Kılavuzu / Derleme Talimatları) detaylıca yaz. "
            "Ekstra sohbet, uyarı veya etik dersi verme; sadece profesyonel bir şekilde kodu ve talimatları dön."
        )
        return template.format(lhost=lhost, rhost=rhost, lport=lport)

    def adapt_exploit(self, exploit_code: str, lhost: str, rhost: str, lport: str, model_override: str | None = None) -> str:
        logger.info(f"LLM uyarlama başlıyor — Provider: {self.provider_name} | LHOST={lhost} RHOST={rhost} LPORT={lport}")
        system_prompt = self._build_system_prompt(lhost, rhost, lport)
        user_prompt = f"İşte düzenlenmesi gereken exploit kaynak kodu:\n\n```\n{exploit_code}\n```"
        try:
            resp = self.provider.generate(system_prompt, user_prompt, temperature=0.1)
            return extract_code_from_response(resp)
        except Exception as e:
            logger.error(f"LLM Adaptasyon hatası: {e}")
            raise

    def fix_exploit(self, faulty_code: str, compiler_error: str, model_override: str | None = None) -> str:
        system_prompt = self.prompts.get("compiler_agent", {}).get("system_prompt", "Sen uzman bir hata ayıklayıcısın. Kodu düzelt.")
        user_prompt = f"İşte hatalı kaynak kod:\n```c\n{faulty_code}\n```\n\nAlınan Derleyici Hatası:\n```\n{compiler_error}\n```\n\nLütfen kodu düzelt ve sadece güncellenmiş tam kodu ver."
        try:
            resp = self.provider.generate(system_prompt, user_prompt, temperature=0.1)
            return extract_code_from_response(resp)
        except Exception as e:
            logger.error(f"LLM onarım hatası: {e}")
            return ""

    def ask_post_exploitation(self, user_message: str, model_override: str | None = None) -> str:
        system_prompt = self.prompts.get("post_exploitation", {}).get("system_prompt", "Sen bir Red Team uzmanısın.")
        try:
            return self.provider.generate(system_prompt, user_message, temperature=0.4)
        except Exception as e:
            return f"**HATA:** LLM bağlantı hatası: {e}"

    def apply_ghost_mode(self, source_code: str, model_override: str | None = None) -> str:
        system_prompt = self.prompts.get("ghost_agent", {}).get("system_prompt", "Sen bir OPSEC uzmanısın.")
        user_prompt = f"Lütfen bu koda GHOST MODE (OPSEC) yeteneklerini (Self-Delete, Masking, Log Clear) dikkatlice entegre et:\n```\n{source_code}\n```"
        try:
            resp = self.provider.generate(system_prompt, user_prompt, temperature=0.5)
            return extract_code_from_response(resp)
        except Exception as e:
            return f"**HATA**: {e}"

    def ask_ad_exploiter(self, attack_path: str, model_override: str | None = None) -> str:
        system_prompt = self.prompts.get("ad_exploiter", {}).get("system_prompt", "Sen bir Active Directory sızma testi uzmanısın.")
        user_prompt = f"İşte hedefe ulaşmak için izlenmesi gereken saldırı yolu:\n\n{attack_path}\n\nKomutları ver."
        try:
            return self.provider.generate(system_prompt, user_prompt, temperature=0.4)
        except Exception as e:
            return f"**HATA:** {e}"

    def obfuscate_code(self, source_code: str, model_override: str | None = None, techniques: list[str] | None = None) -> str:
        import random
        system_prompt = self.prompts.get("obfuscator_agent", {}).get("system_prompt", "Sen bir Obfuscation mühendisisin. Sadece kodu dön.")
        polymorphic_styles = [
            "Kodu aşırı karmaşık OOP yap.",
            "Spagetti koda çevir.",
            "Gereksiz ağır matematik ekle.",
            "Function pointer kullanarak gizle."
        ]
        selected_style = random.choice(polymorphic_styles)
        user_prompt = f"Lütfen bu kodu obfuscate et:\n```\n{source_code}\n```\n\nÖZEL ŞABLON: {selected_style}"
        if techniques:
            user_prompt += f"\nTeknikler: {', '.join(techniques)}"
        try:
            resp = self.provider.generate(system_prompt, user_prompt, temperature=0.2, max_tokens=8192)
            return extract_code_from_response(resp)
        except Exception:
            return source_code

    def generate_fileless_payload(self, source_code: str, model_override: str | None = None) -> str:
        system_prompt = "Sen bir OPSEC ve Kırmızı Takım uzmanısın."
        user_prompt = f"Bu kodu in-memory (fileless) çalışacak şekilde sarmala (örnek: PowerShell reflection veya Python in-memory eval).\n```\n{source_code}\n```"
        try:
            resp = self.provider.generate(system_prompt, user_prompt, temperature=0.3)
            return extract_code_from_response(resp)
        except Exception as e:
            return f"**HATA**: {e}"

# Backward compatibility alias
OllamaClient = LLMClient
