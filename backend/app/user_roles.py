from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.jwt_auth import get_current_admin
from app.schemas import UpdateRoleRequest, ProjectsBase, UsersBase

router = APIRouter(prefix='/api/projects', tags=['Project Users'])


# Зависимость для получения асинхронной сессии БД
async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


# Эндпоинт для просмотра роли пользователя в рамках проекта
@router.get("/{project_id}/users/{user_id}/role")
async def get_user_role(
        project_id: UUID,
        user_id: int,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)  # Добавляем проверку токена
):
    """
    Возвращает текущую роль пользователя в указанном проекте.
    Требует авторизации администратора.
    """
    # Проверка, что администратор имеет доступ к этому проекту
    project_result = await session.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(project_id),
            ProjectsBase.owner_id == current_admin.id
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this project or the project doesn't exist"
        )

    # Проверка существования пользователя в проекте
    result = await session.execute(
        select(UsersBase).where(
            UsersBase.id == user_id,
            cast(UsersBase.project_id, String) == str(project_id)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this project"
        )

    return {"user_id": user.id, "role": user.role}


# Эндпоинт для изменения роли пользователя
@router.put("/{project_id}/users/{user_id}/role")
async def update_user_role(
        project_id: UUID,
        user_id: int,
        request: UpdateRoleRequest,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)  # Добавляем проверку токена
):
    """
    Изменяет роль пользователя в рамках указанного проекта.
    Допустимые значения для new_role: "user" или "admin".
    Требует авторизации администратора, владеющего проектом.
    """
    new_role = request.new_role

    # Проверяем валидность роли
    if new_role not in ("user", "admin"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be 'user' or 'admin'"
        )

    # Проверка, что администратор имеет доступ к этому проекту
    project_result = await session.execute(
        select(ProjectsBase).where(
            cast(ProjectsBase.id, String) == str(project_id),
            ProjectsBase.owner_id == current_admin.id
        )
    )
    project = project_result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to this project or the project doesn't exist"
        )

    # Поиск пользователя
    result = await session.execute(
        select(UsersBase).where(
            UsersBase.id == user_id,
            cast(UsersBase.project_id, String) == str(project_id)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this project"
        )

    # Обновляем поле role
    user.role = new_role
    await session.commit()
    await session.refresh(user)

    # Логирование изменения роли
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        f"Role updated: Admin {current_admin.id} ({current_admin.email}) changed user {user.id} "
        f"({user.email}) role to {new_role} in project {project_id}"
    )

    return {"message": f"User {user.login} role updated to {user.role}"}