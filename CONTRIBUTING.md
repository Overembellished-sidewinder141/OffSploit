# Contributing to OffSploit

OffSploit'e katkıda bulunmak istediğiniz için teşekkürler! Aşağıdaki rehber, katkı sürecini hızlı ve sorunsuz hale getirmenize yardımcı olacaktır.

## Hızlı Başlangıç

1. Repoyu fork'layın ve lokal olarak klonlayın:
   ```bash
   git clone https://github.com/<senin-kullanici-adin>/OffSploit.git
   cd OffSploit
   ```

2. Geliştirme bağımlılıklarını yükleyin:
   ```bash
   pip install -e ".[dev]"
   ```

3. Yeni bir branch oluşturun:
   ```bash
   git checkout -b feature/yeni-ozellik
   ```

## Proje Yapısı

```
offsploit/
├── core_pipeline.py      # Merkezi pipeline orkestratörü
├── nmap_parser.py         # Nmap XML ayrıştırıcı
├── rag_engine.py          # ChromaDB RAG motoru
├── llm_client.py          # LLM provider factory (Ollama/Gemini/OpenAI)
├── swarm_agents.py        # Multi-Agent OPSEC Swarm
├── evasion_engine.py      # Polimorfik evasion motoru
├── docker_sandbox.py      # Docker sandbox (self-healing)
├── payload_engine.py      # Post-exploitation payload motoru
├── state_machine.py       # Otonom pivoting state machine
├── attack_correlator.py   # Nmap + BloodHound korelasyonu
├── compiler_agent.py      # Derleme/syntax kontrolü
├── reporter.py            # PDF rapor üretici
├── exceptions.py          # Özel hata sınıfları
└── response_parser.py     # LLM yanıt ayrıştırıcı
```

## Kod Standartları

- **Linter:** `ruff` kullanıyoruz. PR göndermeden önce temiz çalıştığından emin olun:
  ```bash
  ruff check offsploit/ web/ cli_app.py
  ```
- **Python Sürümü:** Minimum Python 3.10
- **Docstring'ler:** Her public fonksiyon ve sınıf için Türkçe docstring yazın.
- **Exception Handling:** Genel `Exception` yerine `offsploit.exceptions` modülündeki özel hata sınıflarını kullanın.

## Katkı Türleri

### Yeni Evasion Tekniği Eklemek
1. `evasion_engine.py` içindeki `PolymorphicTransform` enum'ına yeni tekniğinizi ekleyin.
2. `LEVEL_TECHNIQUES` sözlüğünde hangi seviyeye dahil olacağını belirtin.
3. `_build_technique_prompt()` metoduna açıklamasını ekleyin.

### Yeni LLM Provider Eklemek
1. `llm_client.py` içinde `LLMProviderInterface`'i implement eden yeni bir sınıf oluşturun.
2. `LLMClient.__init__()` factory metoduna yeni provider'ı ekleyin.

### Yeni Parser Eklemek (Nuclei, Nessus vb.)
1. `offsploit/` altında yeni bir `<tool>_parser.py` dosyası oluşturun.
2. `nmap_parser.py`'deki `ServiceInfo` dataclass'ını referans alın.
3. `core_pipeline.py`'de entegrasyonunu yapın.

## Pull Request Süreci

1. Değişikliklerinizi commit edin.
2. `ruff check` ile lint kontrolü yapın.
3. PR açın ve değişiklikleri açıklayın.
4. Code review bekleyin.

## Yasal Uyarı

Bu projeye katkıda bulunarak, katkılarınızın MIT Lisansı altında lisanslandığını kabul etmiş olursunuz. Katkılarınız yalnızca **yasal sızma testleri ve eğitim amaçlı** kullanılmalıdır.
