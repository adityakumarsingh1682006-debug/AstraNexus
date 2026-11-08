from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """
    AstraNexus Core Configuration
    Loads from environment variables or .env file with defensive defaults.
    """
    PROJECT_NAME: str = "AstraNexus Intelligence Gateway"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # CORS & Security
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://astranexus.vercel.app"
    ]

    # SSRF & Networking Limits
    SSRF_MAX_REDIRECTS: int = 5
    HTTP_TIMEOUT_SECONDS: float = 6.0
    MAX_RESPONSE_BYTES: int = 1024 * 1024  # 1 MB max inspection payload

    # Rate Limiting
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_SCAN: str = "20/minute"

    # AI Engine (Gemini)
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"

    # Supabase (Database & Realtime)
    SUPABASE_URL: Optional[str] = None
    SUPABASE_SERVICE_KEY: Optional[str] = None
    SUPABASE_ANON_KEY: Optional[str] = None

    # Threat Intelligence Feeds
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1"
    URLHAUS_AUTH_KEY: Optional[str] = None
    OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"
    SAFE_BROWSING_API_KEY: Optional[str] = None
    FEED_CACHE_TTL_SECONDS: int = 3600  # 1 hour

    # Blockchain Notary (EVM Testnet)
    EVM_RPC_URL: Optional[str] = None
    ASTRA_REGISTRY_CONTRACT_ADDRESS: Optional[str] = None
    NOTARY_SIGNER_PRIVATE_KEY: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()
