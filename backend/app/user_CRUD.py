from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.security import get_password_hash, password_meets_requirements

from app.database import async_session_maker
from app.schemas import UsersBase, ProjectsBase, UserOut, UsersProjectOut, UserUpdate

router = APIRouter(prefix="/users", tags=["Users CRUD"])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: int, session: AsyncSession = Depends(get_async_session)):
    """
    Возвращает пользователя по его ID.
    """
    result = await session.execute(select(UsersBase).where(UsersBase.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return db_user


@router.get("/project/{project_id}", response_model=UsersProjectOut)
async def get_users_by_project(project_id: int, session: AsyncSession = Depends(get_async_session)):
    """
    Возвращает проект и список пользователей, принадлежащих ему.
    """
    result_project = await session.execute(select(ProjectsBase).where(ProjectsBase.id == project_id))
    project = result_project.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Проект не найден")

    result_users = await session.execute(select(UsersBase).where(UsersBase.project_id == project_id))
    users = result_users.scalars().all()

    return UsersProjectOut(
        project_id=project.id,
        project_name=project.name,
        project_description=project.description,
        users=users,
    )


@router.put("/{user_id}", response_model=UserOut)
async def update_user(user_id: int, user: UserUpdate, session: AsyncSession = Depends(get_async_session)):
    """
    Обновляет данные пользователя по его ID.
    Ожидается JSON с обновляемыми полями (login, email, password).
    Поле project_id изменять не допускается.
    """
    result = await session.execute(select(UsersBase).where(UsersBase.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if user.login is not None:
        db_user.login = user.login

    if user.email is not None:
        db_user.email = user.email

    if user.password is not None:
        # Проверка пароля на сложность
        is_valid, error_message = password_meets_requirements(user.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )
        db_user.password = get_password_hash(user.password)

    await session.commit()
    await session.refresh(db_user)
    return db_user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, session: AsyncSession = Depends(get_async_session)):
    """
    Удаляет пользователя по его ID.
    """
    result = await session.execute(select(UsersBase).where(UsersBase.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    await session.delete(db_user)
    await session.commit()
    return  # При статусе 204 тело ответа не возвращается