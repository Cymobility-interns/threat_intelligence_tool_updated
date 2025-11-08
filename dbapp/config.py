# import os
# from pydantic import BaseSettings

# class Settings(BaseSettings):
#     DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:123456@localhost:5432/vulndb")

# settings = Settings()

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str 
    # openai_api_key: str  
    NVD_API_KEY: str | None = None
    XAI_API_KEY: str | None = None
    debug: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()


if __name__ == "__main__":
    print(Settings().DATABASE_URL)
