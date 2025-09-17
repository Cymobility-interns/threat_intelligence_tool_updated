# import os
# from pydantic import BaseSettings

# class Settings(BaseSettings):
#     DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:123456@localhost:5432/vulndb")

# settings = Settings()

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str 

    openai_api_key: str  

    NVD_API_KEY: str | None = None


    class Config:
        env_file = ".env"

settings = Settings()


if __name__ == "__main__":
    print(Settings().DATABASE_URL)
