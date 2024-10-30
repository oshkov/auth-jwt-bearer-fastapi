from sqlalchemy import select
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta


from src.config import SECRET_KEY, ALGORITHM, HASHING_SCHEME
from src.auth.models import User
from src.auth.schemas import UserRead, UserCreate


# Контекста для хэширования паролей
pwd_context = CryptContext(schemes=HASHING_SCHEME)


# Хэширование пароля
def hash_password(password: str) -> str:
    try:
        hashed_password = pwd_context.hash(password)
        return hashed_password

    except Exception as error:
        raise error


# Проверка пароля
async def verify_password(session, email, plain_password: str) -> bool:
    try:
        # Получение хэшированного пароля пользователя
        result = await session.execute(select(User.hashed_password).filter(User.email == email))
        user_hashed_password = result.scalars().first()
        return pwd_context.verify(plain_password, user_hashed_password)

    except Exception as error:
        raise error


# Проверка наличия пользователя
async def get_user_by_email(session, email):

    try:
        # Проверка на наличие пользователя в таблице
        result = await session.execute(select(User).filter(User.email == email))
        user = result.scalars().first()
        return user

    except Exception as error:
        raise error


# Создание пользователя
async def create_user(session, user: UserCreate):

    try:
        hashed_password = hash_password(user.password)

        user_info = User(
            email = user.email,
            username = user.username,
            registered_at = datetime.utcnow(),
            hashed_password = hashed_password,
            is_active = True,
            is_superuser = False,
            is_verified = False
        )

        # Добавление данных в сессию
        session.add(user_info)

        # Добавление данных в бд и сохранение
        await session.commit()

    except Exception as error:
        raise error


# Создание JWT токена
async def create_access_token(session, user_email) -> str:
    try:
        # Получение данных пользователя
        result = await session.execute(select(User).filter(User.email == user_email))
        user_info = result.scalars().first()

        # Данные для токена
        data = {
            'id': user_info.id,
            'email': user_info.email,
            'username': user_info.username,
            'superuser': user_info.is_superuser,
            'exp': datetime.utcnow() + timedelta(hours=1)  # Установка срока действия токена
        }

        # Создание токена
        encoded_jwt = jwt.encode(data, key=SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    except Exception as error:
        raise error
    

# Получение информации о данном пользователе по JWT токену
async def get_current_user(session, jwt_token):
    try:
        if jwt_token is None:
            return None

        # Получение данных из JWT токена
        data = jwt.decode(jwt_token, key=SECRET_KEY, algorithms=[ALGORITHM])

        # Получение данных пользователя
        result = await session.execute(select(User).filter(User.id == data['id']))
        user_info = result.scalars().first()

        user = UserRead(
            id=user_info.id,
            email=user_info.email,
            username=user_info.username
        )
        return user

    except:
        return None


# Изменение данных пользователя
async def edit_user(session, user, new_user_data):
    try:
        user_info = await session.get(User, user.id)

        user_info.username = new_user_data.username

        # Добавление данных в бд и сохранение
        await session.commit()

    except Exception as error:
        raise error