from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import UpdateRoleRequest

from app.database import async_session_maker
# Импортируем обновлённую ORM-модель с полем role
from init_db import UsersBase

router = APIRouter(prefix="/projects", tags=["User Roles"])

# Зависимость для получения асинхронной сессии БД
async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session

# Эндпоинт для просмотра роли пользователя в рамках проекта
@router.get("/{project_id}/users/{user_id}/role")
async def get_user_role(
    project_id: int,
    user_id: int,
    session: AsyncSession = Depends(get_async_session)
):
    """
    Возвращает текущую роль пользователя в указанном проекте.
    """
    result = await session.execute(
        select(UsersBase).where(
            UsersBase.id == user_id,
            UsersBase.project_id == project_id
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in this project")
    return {"user_id": user.id, "role": user.role}

# Эндпоинт для изменения роли пользователя
@router.put("/{project_id}/users/{user_id}/role")
async def update_user_role(
    project_id: int,
    user_id: int,
    request: UpdateRoleRequest,  # Используем Pydantic модель
    session: AsyncSession = Depends(get_async_session)
):
    """
    Изменяет роль пользователя в рамках указанного проекта.
    Допустимые значения для new_role: "user" или "admin".
    """
    new_role = request.new_role  # Извлекаем new_role из тела запроса

    if new_role not in ("user", "admin"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role must be 'user' or 'admin'")

    result = await session.execute(
        select(UsersBase).where(
            UsersBase.id == user_id,
            UsersBase.project_id == project_id
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in this project")

    # Обновляем поле role
    user.role = new_role
    await session.commit()
    await session.refresh(user)
    return {"message": f"User {user.login} role updated to {user.role}"}