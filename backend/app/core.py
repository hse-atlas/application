# Большинство функций из этого файла перенесены в специализированные модули.
# Оставлены только базовые вспомогательные функции для совместимости.

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.future import select

from app.database import async_session_maker
from app.schemas import AdminsBase, UsersBase


# ----------------------- Функции для администраторов -----------------------

async def find_one_or_none_admin(**filter_by):
    async with async_session_maker() as session:
        query = select(AdminsBase).filter_by(**filter_by)
        result = await session.execute(query)
        return result.scalar_one_or_none()


async def add_admin(**values):
    async with async_session_maker() as session:
        async with session.begin():
            new_instance = AdminsBase(**values)
            session.add(new_instance)
            try:
                await session.commit()
            except SQLAlchemyError as e:
                await session.rollback()
                raise e
            return new_instance


# ----------------------- Функции для пользователей -----------------------

async def find_one_or_none_user(**filter_by):
    async with async_session_maker() as session:
        query = select(UsersBase).filter_by(**filter_by)
        result = await session.execute(query)
        return result.scalar_one_or_none()


async def add_user(**values):
    async with async_session_maker() as session:
        async with session.begin():
            new_instance = UsersBase(**values)
            session.add(new_instance)
            try:
                await session.commit()
            except SQLAlchemyError as e:
                await session.rollback()
                raise e
            return new_instance
