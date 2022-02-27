from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from .schemas import UserCreate, Token


router = APIRouter(prefix='/auth')


@router.post('/sign-up', response_model=Token)
def sign_up(user_data: UserCreate):
    pass


@router.post('/sign-in', response_model=Token)
def sign_in(from_data: OAuth2PasswordRequestForm = Depends()):
    pass
