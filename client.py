import asyncio

import aiohttp


async def main():
    async with aiohttp.ClientSession() as session:
        # Создать пользователя с получением токена
        request = await session.post(
            'http://127.0.0.1:80/user',
            json={"first_name": "Donald",
                  "last_name": "Trump",
                  "email": "donald@trump.com",
                  "password": "P@ssw0rd!"})


        # Получить информацию об аккаунте пользователя
        # request = await session.get('http://127.0.0.1:80/user/5')


        # Изменить информацию в аккаунте пользователя
        # request = await session.patch(
        #     'http://127.0.0.1:80/user/1',
        #     json={'last_name': 'Biden'},
        #     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0fQ.ZEVzAuQIaLvtYBBZOXFGYrutjIZKl2nB_qi_ypQwqfw'})


        # Удалить аккаунт пользователя
        # request = await session.delete(
        #     'http://127.0.0.1:80/user/1',
        #     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo1fQ.q8ahqrVpgC8x8xvTNgwjxsmf2OsSN7RXrbxDICfz6pU'})


        # Создать объявление
        # request = await session.post(
        #     'http://127.0.0.1:80/advert',
        #     json={'title': 'iPhone 16 Pro', 'description': 'новый'},
        #     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0fQ.ZEVzAuQIaLvtYBBZOXFGYrutjIZKl2nB_qi_ypQwqfw'})


        # Получить объявление
        # request = await session.get('http://127.0.0.1:80/advert/1')


        # Изменить объявление
        # request = await session.patch(
        #     'http://127.0.0.1:80/advert/1',
        #     json={'description': 'б/у'},
        #     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0fQ.ZEVzAuQIaLvtYBBZOXFGYrutjIZKl2nB_qi_ypQwqfw'})


        # Удалить объявление
        # request = await session.delete(
        #     'http://127.0.0.1:80/advert/1',
        #     headers={'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.LwkgCOElcw3-Pjhj929-HrRYoHPRSShi7pRA-97TPt0'})
        #
        # print(await request.json())
        # print(request.status)


if __name__ == '__main__':
    asyncio.run(main())
