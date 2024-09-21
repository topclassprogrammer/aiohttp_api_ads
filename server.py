import json
import os
from typing import Callable

import bcrypt
import jwt
from aiohttp import web
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from typing_extensions import Type

from models import Advert, SessionDB, User, engine, init_orm
from schema import CreateAdvert, CreateUser, UpdateAdvert, UpdateUser

# Секретный ключ для подписи токена
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")


async def orm_context(app):
    """Инициализируем БД и ORM-модели"""
    await init_orm()
    yield
    await engine.dispose()


def hash_password(password: str) -> str:
    """Хешируем пароль получаемый от пользователя"""
    password = password.encode()
    password = bcrypt.hashpw(password, bcrypt.gensalt())
    password = password.decode()
    return password


@web.middleware
async def session_middleware(request: web.Request, handler):
    """Создаем сессию работы с БД при каждом HTTP-запросе"""
    async with SessionDB() as session:
        request.session = session
        response = await handler(request)
        return response


def get_http_error(error_cls, msg: str | dict | list) -> web.HTTPClientError:
    """Перехватываем класс исключений aiohttp"""
    return error_cls(text=json.dumps({"error": msg}),
                     content_type="application/json")


def require_token(func: Callable) -> Callable:
    """Декоратор для оборачивания тех HTTP-методов
    для которых нужна авторизация по токену"""

    async def wrapper(self: User | Advert) -> Callable | web.Response:
        token = self.request.headers.get("Authorization")
        if not token:
            return web.json_response({"error": "No token provided"})
        try:
            jwt.decode(jwt=token.split()[-1], key=JWT_SECRET_KEY,
                       algorithms=["HS256"])
        except jwt.exceptions.DecodeError:
            return web.json_response({"error": "Invalid token"})
        return await func(self)

    return wrapper


class BaseView:
    """Базовый класс для View-классов"""

    @property
    def session(self) -> AsyncSession:
        """Получаем сессию работы с БД"""
        return self.request.session

    @staticmethod
    async def get_user_by_id(user_id: int, session: AsyncSession) -> User:
        """Получение объекта класса User из БД"""
        user = await session.get(User, user_id)
        if user is None:
            raise get_http_error(web.HTTPNotFound, "User not found")
        return user

    @staticmethod
    async def get_advert_by_id(advert_id: int, session: AsyncSession) \
            -> Advert:
        """Получение объекта класса Advert из БД"""
        advert = await session.get(Advert, advert_id)
        if advert is None:
            raise get_http_error(
                web.HTTPNotFound, "Advert not found")
        return advert

    def get_user_id_from_token(self):
        token = self.request.headers.get('Authorization')
        payload = jwt.decode(jwt=token.split()[-1], key=JWT_SECRET_KEY,
                             algorithms=["HS256"])
        return payload.get("user_id")

    @staticmethod
    def validate_json(
            json_data: dict,
            schema_cls: (Type[CreateUser] | Type[UpdateUser] |
                         Type[CreateAdvert] | Type[UpdateAdvert])
    ) -> dict:
        """Валидация входящих JSON данных от клиента"""
        try:
            return schema_cls(**json_data).dict(exclude_unset=True)
        except ValidationError as err:
            errors = err.errors()
            for error in errors:
                error.pop("ctx", None)
            raise get_http_error(web.HTTPBadRequest, errors)


class UserView(web.View, BaseView):
    """Класс пользователей"""

    @property
    def user_id(self) -> int:
        return int(self.request.match_info["user_id"])

    @staticmethod
    async def add_user(user: User, session: AsyncSession) -> User:
        """Создание/изменение пользователя в БД"""
        session.add(user)
        try:
            await session.commit()
        except IntegrityError:
            raise get_http_error(web.HTTPConflict, "User already exists")
        return user

    async def check_user_possession(self):
        """Проверяем принадлежит ли пользователю аккаунт
        над которым он совершает действие"""
        user_id_from_token = self.get_user_id_from_token()
        if self.user_id != user_id_from_token:
            raise get_http_error(web.HTTPUnauthorized,
                                 "Account does not belong to you", )

    async def generate_token(self, user_id: int) -> str:
        """Генерируем токен"""
        payload = {"user_id": user_id}
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

    async def get(self) -> web.Response:
        """Запрос от клиента на получение информации из аккаунта"""
        user = await self.get_user_by_id(self.user_id, self.session)
        return web.json_response(user.json, status=200)

    async def post(self) -> web.Response:
        """Запрос от клиента на создание аккаунта"""
        json_data = await self.request.json()
        json_data = self.validate_json(json_data, CreateUser)
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        user = await self.add_user(user, self.session)
        token = await self.generate_token(user.id)
        user.token = token
        await self.request.session.commit()
        return web.json_response({"id": user.id}, status=201)

    @require_token
    async def patch(self) -> web.Response:
        """Запрос от клиента на обновление информации в аккаунте"""
        await self.check_user_possession()
        json_data = await self.request.json()
        json_data = self.validate_json(json_data, UpdateUser)
        if json_data.get("password"):
            json_data["password"] = hash_password(json_data["password"])
        user = await self.get_user_by_id(self.user_id, self.session)
        for k, v in json_data.items():
            setattr(user, k, v)
        user = await self.add_user(user, self.session)
        return web.json_response({"id": user.id}, status=206)

    @require_token
    async def delete(self) -> web.Response:
        """Запрос от клиента на удаление аккаунта"""
        await self.check_user_possession()
        user = await self.get_user_by_id(self.user_id, self.session)
        await self.session.delete(user)
        await self.session.commit()
        return web.json_response({"status": "deleted"}, status=204)


class AdvertView(web.View, BaseView):
    """Класс объявлений"""

    @property
    def advert_id(self) -> int:
        return int(self.request.match_info["advert_id"])

    async def add_advert(self, advert: Advert, session: AsyncSession) \
            -> Advert:
        """Создание/изменение объявления в БД"""
        owner = await self.get_user_by_id(advert.owner, session)
        if not owner:
            raise get_http_error(
                web.HTTPNotFound, "Advert owner not found"
            )
        session.add(advert)
        await session.commit()
        return advert

    async def check_advert_possession(self):
        """Проверяем принадлежит ли пользователю объявление
        над которым он совершает действие"""
        user_id_from_token = self.get_user_id_from_token()
        async with SessionDB() as session:
            advert = await session.get(Advert, self.advert_id)
        if advert.owner != user_id_from_token:
            raise get_http_error(web.HTTPUnauthorized,
                                 "Advert does not belong to you")

    async def get(self) -> web.Response:
        """Запрос от клиента на получение информации об объявлении"""
        advert = await self.get_advert_by_id(self.advert_id, self.session)
        return web.json_response(advert.json, status=200)

    @require_token
    async def post(self) -> web.Response:
        """Запрос от клиента на создание объявления"""
        json_data = await self.request.json()
        json_data = self.validate_json(json_data, CreateAdvert)
        owner_id_from_token = self.get_user_id_from_token()
        json_data["owner"] = owner_id_from_token
        advert = Advert(**json_data)
        advert = await self.add_advert(advert, self.session)
        return web.json_response({"id": advert.id}, status=201)

    @require_token
    async def patch(self) -> web.Response:
        """Запрос от клиента на обновление информации в объявлении"""
        await self.check_advert_possession()
        json_data = await self.request.json()
        json_data = self.validate_json(json_data, UpdateAdvert)
        advert = await self.get_advert_by_id(self.advert_id, self.session)
        for k, v in json_data.items():
            setattr(advert, k, v)
        advert = await self.add_advert(advert, self.session)
        return web.json_response({"id": advert.id}, status=206)

    @require_token
    async def delete(self) -> web.Response:
        """Запрос от клиента на удаление объявления"""
        await self.check_advert_possession()
        advert = await self.get_advert_by_id(self.advert_id, self.session)
        await self.session.delete(advert)
        await self.session.commit()
        return web.json_response({"status": "deleted"}, status=204)


if __name__ == "__main__":
    app = web.Application()

    app.cleanup_ctx.append(orm_context)
    app.middlewares.append(session_middleware)

    app.add_routes(
        [
            web.get(r"/user/{user_id:\d+}", UserView),
            web.post("/user", UserView),
            web.patch(r"/user/{user_id:\d+}", UserView),
            web.delete(r"/user/{user_id:\d+}", UserView),
            web.get(r"/advert/{advert_id:\d+}", AdvertView),
            web.post("/advert", AdvertView),
            web.patch(r"/advert/{advert_id:\d+}", AdvertView),
            web.delete(r"/advert/{advert_id:\d+}", AdvertView),
        ]
    )

    web.run_app(app, host="0.0.0.0", port=8000)
