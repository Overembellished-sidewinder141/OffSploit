"""
OffSploit — Autonomous Red Team Weapon
========================================
RAG + Local LLM destekli otonom sızma testi ve
exploit uyarlama aracı. Docker sandbox, multi-agent
OPSEC doğrulama, polimorfik evasion ve state machine
tabanlı pivoting yetenekleri ile gelişmiş bir Red Team silahı.
"""

__version__ = "1.0.0"
__author__ = "Egnake"

from offsploit.exceptions import (
    AttackCorrelationError,
    CompilerError,
    ConfigError,
    DockerSandboxError,
    EvasionError,
    IngestError,
    NmapParseError,
    OffSploitError,
    OllamaAPIError,
    OllamaConnectionError,
    OllamaTimeoutError,
    PayloadError,
    RAGSearchError,
    StateMachineError,
    SwarmAgentError,
)

__all__ = [
    "__version__",
    "__author__",
    "OffSploitError",
    "NmapParseError",
    "RAGSearchError",
    "OllamaConnectionError",
    "OllamaTimeoutError",
    "OllamaAPIError",
    "CompilerError",
    "ConfigError",
    "IngestError",
    "DockerSandboxError",
    "SwarmAgentError",
    "EvasionError",
    "StateMachineError",
    "PayloadError",
    "AttackCorrelationError",
]
