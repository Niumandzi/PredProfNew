from pydantic import BaseSettings


class Settings(BaseSettings):
    jwt_secret: str
    jwt_algorithm: str = 'H5256'
    jwt_expiration: int = 3600
