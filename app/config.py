from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Loaded from .env (see .env.example).
    database_url: str = "sqlite:///./user_management.db"
    secret_key: str = "change-me-to-a-long-random-string"
    access_token_expire_minutes: int = 30  # Plan: 30-minute access tokens.
    algorithm: str = "HS256"
    default_department: str = "unassigned"  # Applied at registration; admin can change later.

    # Only consumed by the seed script.
    admin_email: str | None = None
    admin_password: str | None = None

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")


settings = Settings()
