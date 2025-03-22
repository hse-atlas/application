import logging
from datetime import datetime
from typing import Annotated, Dict, Any, Optional

from sqlalchemy import func, JSON
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs
from sqlalchemy.future import select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import get_pass_db_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = get_pass_db_url()
engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

int_pk = Annotated[int, mapped_column(primary_key=True)]
created_at = Annotated[datetime, mapped_column(server_default=func.now())]
updated_at = Annotated[datetime, mapped_column(server_default=func.now(), onupdate=datetime.now)]
str_uniq = Annotated[str, mapped_column(unique=True, nullable=False)]
str_null_true = Annotated[str, mapped_column(nullable=True)]
json_field = Annotated[Optional[Dict[str, Any]], mapped_column(JSON, nullable=True)]


class Base(AsyncAttrs, DeclarativeBase):
    __abstract__ = True

    created_at: Mapped[created_at]
    updated_at: Mapped[updated_at]


async def test_db_connection():
    try:
        async with async_session_maker() as session:
            await session.execute(select(1))
        logger.info("Database connection successful")
    except Exception as error:
        logger.error(f"❌ Database cannot connect, startup will be aborted: {error}")
        exit(1)