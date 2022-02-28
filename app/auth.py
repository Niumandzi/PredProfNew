from datetime import datetime,timedelta
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from passlib.hash import bcrypt
from pydantic import ValidationError
from auth import models
from auth.schemas import User, UserCreate, Token
from core.settings import Settings
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer


def get_session():
    session = Session()
    try:
        yield session
    finally:
        session.close()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/sign-in/')


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return AuthService.validate_token(token)


class AuthService:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    #проверка токена
    @classmethod
    def validate_token(cls, token: str) -> User:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={
                'WWW-Authenticate': 'Bearer'
            },
        )

        try:
            payload = jwt.decode(
                token,
                Settings.jwt_secret,
                algorithms=[Settings.jwt_algorithm]
            )

        except JWTError:
            raise exception from None

        user_data = payload.get('user')

        try:
            user = User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    #создание токена
    @classmethod
    def create_token(cls, user: models.User) -> Token:
        user_data = User.from_orm(user)

        now = datetime.now()

        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=Settings.jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.dict(),
        }
        token = jwt.encode(
            payload,
            Settings.jwt_secret,
            algorithm=Settings.jwt_algorithm,
        )

        return Token(acces_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: UserCreate) -> Token:
        user = models.User(
            username=user_data.username,
            password_hash=self.hash_password(user_data.password),
        )
        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    def authenticate_user(self, username: str, password: str) -> Token:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={
                'WWW-Authenticate': 'Bearer'
            },
        )
        user = (
            self.session
            .query(models.User)
            .filter(models.User.username == username)
            .first()
        )

        if not user:
            raise exception

        if not self.verify_password(password, user.password_hash):
            raise exception

        return self.create_token(user)
