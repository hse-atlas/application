from uuid import UUID
from sqlalchemy import select, cast, String
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import APIRouter, Depends, HTTPException, status

from app.database import async_session_maker
from app.jwt_auth import get_current_admin
from app.schemas import UsersBase, ProjectsBase, UserOut, UsersProjectOut, UserUpdate
from app.security import get_password_hash, password_meets_requirements

router = APIRouter(prefix='/api/users', tags=['Users CRUD'])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
        user_id: int,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)
):
    """
    Возвращает пользователя по его ID.
    """
    # Сначала находим пользователя для получения его project_id
    result = await session.execute(select(UsersBase).where(UsersBase.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверяем, владеет ли текущий админ проектом, к которому принадлежит пользователь
    project_result = await session.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(db_user.project_id),
            ProjectsBase.owner_id == current_admin.id
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="У вас нет прав для просмотра этого пользователя"
        )

    return db_user


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
        user_id: int,
        user: UserUpdate,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)
):
    """
    Обновляет данные пользователя по его ID.
    Ожидается JSON с обновляемыми полями (login, email, password).
    Поле project_id изменять не допускается.
    """
    # Сначала находим пользователя для получения его project_id
    result = await session.execute(select(UsersBase).where(UsersBase.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверяем, владеет ли текущий админ проектом, к которому принадлежит пользователь
    project_result = await session.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(db_user.project_id),
            ProjectsBase.owner_id == current_admin.id
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="У вас нет прав для изменения этого пользователя"
        )

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
async def delete_user(
        user_id: int,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)
):
    """
    Удаляет пользователя по его ID.
    """
    # Сначала находим пользователя для получения его project_id
    result = await session.execute(select(UsersBase).where(UsersBase.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверяем, владеет ли текущий админ проектом, к которому принадлежит пользователь
    project_result = await session.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(db_user.project_id),
            ProjectsBase.owner_id == current_admin.id
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="У вас нет прав для удаления этого пользователя"
        )

    await session.delete(db_user)
    await session.commit()
    return  # При статусе 204 тело ответа не возвращается


@router.get("/project/{project_id}", response_model=UsersProjectOut)
async def get_users_by_project(
        project_id: UUID,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)
):
    """
    Возвращает проект и список пользователей, принадлежащих ему.
    """
    # Проверяем, владеет ли текущий админ данным проектом
    result_project = await session.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(project_id),
            ProjectsBase.owner_id == current_admin.id
        )
    )
    project = result_project.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="У вас нет прав для просмотра этого проекта или проект не существует"
        )

    result_users = await session.execute(
        select(UsersBase).where(
            cast(UsersBase.project_id, String) == str(project_id)
        )
    )
    users = result_users.scalars().all()

    return UsersProjectOut(
        project_id=project.id,
        project_name=project.name,
        project_description=project.description,
        users=users,
    )