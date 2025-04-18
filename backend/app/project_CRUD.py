from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_maker
from app.jwt_auth import get_current_admin
from app.schemas import (
    ProjectsBase,
    UsersBase,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    ProjectDetailResponse,
    UserResponse,
    ProjectOAuthSettings,
)

#router = APIRouter(prefix="/projects", tags=["Projects CRUD"])
router = APIRouter(tags=["Projects CRUD"])


async def get_async_session() -> AsyncSession:
    async with async_session_maker() as session:
        yield session


@router.post("/", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
        project: ProjectCreate,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)
):
    """
    Создает новый проект.
    """


    new_project = ProjectsBase(
        name=project.name,
        description=project.description,
        owner_id=current_admin.id,
        url=project.url,
        oauth_enabled=project.oauth_enabled,
        oauth_providers=project.oauth_providers.dict() if project.oauth_providers else None,
    )
    session.add(new_project)
    await session.commit()
    await session.refresh(new_project)

    # Так как проект только создан, количество пользователей равно 0
    return ProjectOut(
        id=new_project.id,
        name=new_project.name,
        description=new_project.description,
        owner_id=new_project.owner_id,
        url=new_project.url,
        user_count=0,
        oauth_enabled=new_project.oauth_enabled,
    )


@router.put("/owner/{project_id}", response_model=ProjectOut)
async def update_project(
        project_id: int,
        project: ProjectUpdate,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin),
):
    """
    Обновляет проект.
    """
    result = await session.execute(
        select(ProjectsBase).where(ProjectsBase.id == project_id)
    )
    db_project = result.scalar_one_or_none()
    if not db_project:
        raise HTTPException(status_code=404, detail="Проект не найден")

    if db_project.owner_id != current_admin.id:
        raise HTTPException(
            status_code=403, detail="Нет прав для изменения этого проекта"
        )

    if project.name is not None:
        db_project.name = project.name
    if project.description is not None:
        db_project.description = project.description
    if project.url is not None:
        db_project.url = project.url
    if project.oauth_enabled is not None:
        db_project.oauth_enabled = project.oauth_enabled
    if project.oauth_providers is not None:
        db_project.oauth_providers = project.oauth_providers.dict()

    await session.commit()
    await session.refresh(db_project)

    result_count = await session.execute(
        select(func.count(UsersBase.id)).where(UsersBase.project_id == db_project.id)
    )
    user_count = result_count.scalar() or 0

    return ProjectOut(
        id=db_project.id,
        name=db_project.name,
        description=db_project.description,
        owner_id=db_project.owner_id,
        url=db_project.url,
        user_count=user_count,
        oauth_enabled=db_project.oauth_enabled,
    )


@router.delete("/owner/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
        project_id: int,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin),
):
    """
    Удаляет проект, если запрос исходит от его владельца.
    """
    result = await session.execute(
        select(ProjectsBase).where(ProjectsBase.id == project_id)
    )
    db_project = result.scalar_one_or_none()
    if not db_project:
        raise HTTPException(status_code=404, detail="Проект не найден")

    if db_project.owner_id != current_admin.id:
        raise HTTPException(
            status_code=403, detail="Нет прав для удаления этого проекта"
        )

    await session.delete(db_project)
    await session.commit()
    return  # 204 No Content


@router.get("/owner", response_model=List[ProjectOut])
async def list_admin_projects(
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin),
):
    """
    Возвращает список всех проектов текущего администратора с количеством пользователей.
    """
    stmt = (
        select(
            ProjectsBase.id,
            ProjectsBase.name,
            ProjectsBase.description,
            ProjectsBase.owner_id,
            ProjectsBase.url,
            ProjectsBase.oauth_enabled,
            func.count(UsersBase.id).label("user_count"),
        )
        .outerjoin(UsersBase, UsersBase.project_id == ProjectsBase.id)
        .where(ProjectsBase.owner_id == current_admin.id)
        .group_by(ProjectsBase.id)
    )
    result = await session.execute(stmt)
    projects = result.all()

    if not projects:
        return []

    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "owner_id": p.owner_id,
            "url": p.url,
            "user_count": p.user_count,
            "oauth_enabled": p.oauth_enabled,
        }
        for p in projects
    ]


@router.get("/{project_id}", response_model=ProjectDetailResponse)
async def get_project_details(
        project_id: int,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin),
):
    """
    Получение деталей проекта, включая список пользователей с их ролями.
    """
    # Основной запрос для получения проекта
    project_stmt = (
        select(
            ProjectsBase.id,
            ProjectsBase.name,
            ProjectsBase.description,
            ProjectsBase.owner_id,
            ProjectsBase.url,
            ProjectsBase.oauth_enabled,
            ProjectsBase.oauth_providers,
            func.count(UsersBase.id).label("user_count"),
        )
        .outerjoin(UsersBase, UsersBase.project_id == ProjectsBase.id)
        .where(ProjectsBase.id == project_id, ProjectsBase.owner_id == current_admin.id)
        .group_by(ProjectsBase.id)
    )
    project_result = await session.execute(project_stmt)
    project_row = project_result.first()
    
    if not project_row:
        raise HTTPException(
            status_code=404, detail="Проект не найден или доступ запрещён"
        )

    # Запрос для получения пользователей с их ролями
    users_stmt = (
        select(
            UsersBase.id,
            UsersBase.login,
            UsersBase.email,
            UsersBase.role,  # Добавляем поле с ролью
            UsersBase.oauth_provider
        )
        .where(UsersBase.project_id == project_id)
    )
    
    users_result = await session.execute(users_stmt)
    users = users_result.all()

    # Формируем ответ с ролями
    user_responses = [
        UserResponse(
            id=user.id,
            login=user.login,
            email=user.email,
            role=user.role,  # Добавляем роль в ответ
            oauth_provider=user.oauth_provider
        ) for user in users
    ]

    # Обработка OAuth providers
    oauth_providers = None
    if project_row.oauth_providers:
        oauth_providers = ProjectOAuthSettings.parse_obj(project_row.oauth_providers)

    return ProjectDetailResponse(
        id=project_row.id,
        name=project_row.name,
        description=project_row.description,
        owner_id=project_row.owner_id,
        url=project_row.url,
        user_count=project_row.user_count,
        users=user_responses,
        oauth_enabled=project_row.oauth_enabled,
        oauth_providers=oauth_providers,
    )


@router.get("/getURL/{project_id}", response_model=str)
async def get_project_url(
        project_id: int,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin)
):
    """
    Получение URL проекта по его ID.
    """
    # Проверяем, владеет ли текущий админ данным проектом
    stmt = select(ProjectsBase).where(
        ProjectsBase.id == project_id,
        ProjectsBase.owner_id == current_admin.id
    )
    result = await session.execute(stmt)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="У вас нет прав для просмотра URL этого проекта или проект не существует"
        )

    return project.url


@router.put("/{project_id}/oauth", response_model=ProjectOut)
async def update_project_oauth(
        project_id: int,
        oauth_settings: ProjectOAuthSettings,
        session: AsyncSession = Depends(get_async_session),
        current_admin=Depends(get_current_admin),
):
    """
    Обновляет настройки OAuth для проекта.
    """
    result = await session.execute(
        select(ProjectsBase).where(ProjectsBase.id == project_id)
    )
    db_project = result.scalar_one_or_none()
    if not db_project:
        raise HTTPException(status_code=404, detail="Проект не найден")

    if db_project.owner_id != current_admin.id:
        raise HTTPException(
            status_code=403, detail="Нет прав для изменения этого проекта"
        )

    db_project.oauth_enabled = oauth_settings.enabled
    db_project.oauth_providers = oauth_settings.dict()

    await session.commit()
    await session.refresh(db_project)

    result_count = await session.execute(
        select(func.count(UsersBase.id)).where(UsersBase.project_id == db_project.id)
    )
    user_count = result_count.scalar() or 0

    return ProjectOut(
        id=db_project.id,
        name=db_project.name,
        description=db_project.description,
        owner_id=db_project.owner_id,
        url=db_project.url,
        user_count=user_count,
        oauth_enabled=db_project.oauth_enabled,
    )