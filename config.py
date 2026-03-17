"""Configuration module - loads settings from environment variables."""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import List, Optional
from functools import lru_cache
import ipaddress


class Settings(BaseSettings):
    """Application configuration loaded from .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Application
    soar_host: str = Field(default="0.0.0.0")
    soar_port: int = Field(default=8080)
    soar_env: str = Field(default="production")
    soar_log_level: str = Field(default="INFO")
    soar_webhook_secret: str = Field(description="HMAC secret for webhook validation")

    # Threat Intelligence
    abuseipdb_api_key: str = Field(description="AbuseIPDB API key")
    virustotal_api_key: str = Field(description="VirusTotal API key")

    # AI Engine
    ai_provider: str = Field(default="ollama")
    openai_api_key: Optional[str] = Field(default=None)
    openai_model: str = Field(default="gpt-4-turbo-preview")
    openai_timeout: int = Field(default=30)
    ollama_host: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.1")

    # Slack
    slack_webhook_url: str = Field(description="Slack incoming webhook URL")
    slack_channel: str = Field(default="#soc-alerts")

    # Response Engine
    enable_auto_block: bool = Field(default=True)
    block_duration_hours: int = Field(default=24)
    whitelist_ips: str = Field(default="10.0.0.0/8,192.168.0.0/16,127.0.0.1")

    # Thresholds
    block_score_threshold: int = Field(default=75)
    escalate_score_threshold: int = Field(default=50)

    # Cache
    cache_ttl_seconds: int = Field(default=3600)

    @field_validator("soar_log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"Log level must be one of {valid}")
        return v.upper()

    def get_whitelist_networks(self) -> List[ipaddress.IPv4Network]:
        """Parse whitelist IPs/CIDRs into network objects."""
        networks = []
        for entry in self.whitelist_ips.split(","):
            entry = entry.strip()
            if entry:
                try:
                    networks.append(ipaddress.IPv4Network(entry, strict=False))
                except ValueError:
                    pass
        return networks

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP address is in the whitelist."""
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in self.get_whitelist_networks())
        except ValueError:
            return False


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance (singleton pattern)."""
    return Settings()
