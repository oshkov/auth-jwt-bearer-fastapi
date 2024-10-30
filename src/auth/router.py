from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse

from src.database import get_async_session
from src.auth.utils import (
    create_user,
    verify_password,
    create_access_token,
    get_user_by_email,
    get_current_user,
    edit_user
)
from src.auth.schemas import UserCreate, UserLogin, UserEdit


router = APIRouter(
    tags=['Auth']
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token-for-docs')

@router.post('/token-for-docs')
async def token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session = Depends(get_async_session)
):
    '''
    Эндпоинт для получения токена в документации
    '''

    try:
        email = form_data.username
        password = form_data.password

        # Проверка пароля пользователя
        if await verify_password(session, email, password):

            # Создание JWT токена
            jwt_token = await create_access_token(session, password)

            response_data = {
                'status': 'success',
                'data': {
                    'access_token': jwt_token,
                    'token_type': 'bearer'
                },
                'detail': None,
                'access_token': jwt_token,
            }
            response = JSONResponse(content=response_data, status_code=200)

            return response

        # Ошибка авторизации
        else:
            raise HTTPException(status_code=400, detail='Invalid credentials')
        
    # Обработка ошибок
    except HTTPException as error:
        response_data = {
            'status': 'error',
            'data': None,
            'detail': error.detail
        }
        return JSONResponse(content=response_data, status_code=error.status_code)

    # Ошибка сервера
    except Exception as error:
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)


@router.post('/register')
async def register(
    user: UserCreate,
    session = Depends(get_async_session)
):
    '''
    Регистрация пользователя
    '''

    try:
        # Проверка пользователя на регистрацию
        user_in_db = await get_user_by_email(session, user.email)

        # Вывод ошибки если пользователь был зарегистрирован
        if user_in_db:
            raise HTTPException(status_code=409, detail='User already registered')

        # Создаение пользователя
        await create_user(session, user)

        jwt_token = await create_access_token(session, user.email)

        response_data = {
                'status': 'success',
                'data': {
                    'access_token': jwt_token,
                    'token_type': 'bearer'
                },
                'detail': None
            }
        response = JSONResponse(content=response_data, status_code=200)

        return response

    # Обработка ошибок
    except HTTPException as error:
        response_data = {
            'status': 'error',
            'data': None,
            'detail': error.detail
        }
        return JSONResponse(content=response_data, status_code=error.status_code)

    # Ошибка сервера
    except Exception as error:
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)
    

@router.post('/login')
async def login(
    user: UserLogin,
    session = Depends(get_async_session)
):
    '''
    Вход в аккаунт
    '''

    try:
        # Проверка пароля пользователя
        if await verify_password(session, user.email, user.password):

            # Создание JWT токена
            jwt_token = await create_access_token(session, user.email)

            response_data = {
                'status': 'success',
                'data': {
                    'access_token': jwt_token,
                    'token_type': 'bearer'
                },
                'detail': None
            }
            response = JSONResponse(content=response_data, status_code=200)

            return response

        # Ошибка авторизации
        else:
            raise HTTPException(status_code=400, detail='Invalid credentials')

    # Обработка ошибок
    except HTTPException as error:
        response_data = {
            'status': 'error',
            'data': None,
            'detail': error.detail
        }
        return JSONResponse(content=response_data, status_code=error.status_code)

    # Ошибка сервера
    except Exception as error:
        print(error)
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)


@router.post('/edit-profile')
async def edit_profile(
    new_user_data: UserEdit,
    token = Depends(oauth2_scheme),
    session = Depends(get_async_session)
):
    '''
    Редактирование имени по паролю
    '''

    try:
        user = await get_current_user(session, token)

        # Проверка пароля
        if await verify_password(session, user.email, new_user_data.password):

            # Изменение данных профиля
            await edit_user(session, user, new_user_data)

            # Создание JWT токена
            jwt_token = await create_access_token(session, user.email)

            response_data = {
                'status': 'success',
                'data': {
                    'access_token': jwt_token,
                    'token_type': 'bearer'
                },
                'detail': None
            }
            response = JSONResponse(content=response_data, status_code=200)

            return response

        else:
            raise HTTPException(status_code=400, detail='Password is incorrect')

    # Обработка ошибок
    except HTTPException as error:
        response_data = {
            'status': 'error',
            'data': None,
            'detail': error.detail
        }
        return JSONResponse(content=response_data, status_code=error.status_code)

    # Ошибка сервера
    except Exception as error:
        print(error)
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)


@router.get('/get-current-user')
async def get_current_user_route(
    token: str = Depends(oauth2_scheme),
    session = Depends(get_async_session)
):
    '''
    Аутентификация пользователя
    '''

    try:
        user = await get_current_user(session, token)

        if user == None:
            raise HTTPException(status_code=401, detail='Unauthorized')

        user_json = {
            'id': user.id,
            'email': user.email,
            'username': user.username
        }

        response_data = {
            'status': 'success',
            'data': user_json,
            'detail': None
        }

        response = JSONResponse(content=response_data)

        return response

    # Обработка ошибок
    except HTTPException as error:
        response_data = {
            'status': 'error',
            'data': None,
            'detail': error.detail
        }
        return JSONResponse(content=response_data, status_code=error.status_code)

    # Ошибка сервера
    except Exception as error:
        response_data = {
            'status': 'error',
            'data': str(error),
            'detail': 'Server error'
        }
        return JSONResponse(content=response_data, status_code=500)