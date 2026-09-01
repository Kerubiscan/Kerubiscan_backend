from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Kimia Vulnerability Scanner"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    POSTGRES_URL: str = "postgresql://kimia:kimia_password@localhost:5432/kimia_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Keycloak
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"
    KEYCLOAK_REALM_NAME: str = "kimia"
    KEYCLOAK_CLIENT_ID: str = "kimia-backend"
    KEYCLOAK_CLIENT_SECRET: str = ""
    
    class Config:

        case_sensitive = True
        env_file = ".env"

settings = Settings()
