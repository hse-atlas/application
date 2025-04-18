import pytest
from fastapi.testclient import TestClient
from sqlalchemy.sql.selectable import Select
from backend.app.main import application
from app.admin_auth import get_current_admin
from app.user_CRUD import get_async_session
from app.schemas import ProjectOAuthSettings, UsersBase, ProjectsBase

BASE = "/api/v1/AuthService"

class FakeAdmin:
    def __init__(self, id=1, login="admin", email="admin@example.com", password="hashedpwd"):
        self.id = id
        self.login = login
        self.email = email
        self.password = password

@pytest.fixture(scope="module")
def client():
    return TestClient(application)

@pytest.fixture(autouse=True)
def override_redis(monkeypatch):
    class FakeRedis:
        async def setex(self, *a, **kw): pass
    monkeypatch.setattr("app.jwt_auth.redis_client", FakeRedis())

# -------------------- User CRUD tests --------------------

@pytest.mark.asyncio
async def test_get_user(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeUser:
        id = 1
        login = "user"
        email = "user@example.com"
        project_id = 2

    class FakeProject:
        id = 2
        owner_id = 1

    class FakeSession:
        async def execute(self, stmt):
            model = stmt.column_descriptions[0]["entity"]
            if model is UsersBase:
                class Result:
                    def scalar_one_or_none(self): return FakeUser()
                return Result()
            else:
                class Result:
                    def scalar_one_or_none(self): return FakeProject()
                return Result()

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.get("/users/1")
    assert response.status_code == 200
    assert response.json()["email"] == "user@example.com"

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_get_users_by_project(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeProject:
        id = 1
        name = "Test Project"
        description = "Desc"
        owner_id = 1

    class FakeUser:
        id = 1
        login = "user"
        email = "user@example.com"
        project_id = 1

    class FakeSession:
        async def execute(self, stmt):
            model = stmt.column_descriptions[0]["entity"]
            if model is ProjectsBase:
                class Result:
                    def scalar_one_or_none(self): return FakeProject()
                return Result()
            else:
                class Result:
                    def scalars(self):
                        class Scalar:
                            def all(self): return [FakeUser()]
                        return Scalar()
                return Result()

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.get("/users/project/1")
    assert response.status_code == 200
    assert response.json()["project_name"] == "Test Project"

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_update_user(monkeypatch, client):
    from app.security import get_password_hash

    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeUser:
        id = 1
        login = "user"
        email = "user@example.com"
        project_id = 2
        password = "hashedpwd"

    class FakeProject:
        id = 2
        owner_id = 1

    class FakeSession:
        async def execute(self, stmt):
            model = stmt.column_descriptions[0]["entity"]
            if model is UsersBase:
                class Result:
                    def scalar_one_or_none(self): return FakeUser()
                return Result()
            else:
                class Result:
                    def scalar_one_or_none(self): return FakeProject()
                return Result()
        async def commit(self): pass
        async def refresh(self, obj): pass

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    payload = {"login": "updated_user", "password": "StrongPass123!"}
    client.cookies.set("users_access_token", "token")
    response = client.put("/users/1", json=payload)

    assert response.status_code == 200
    assert response.json()["login"] == "updated_user"

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_delete_user(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeUser:
        id = 1
        project_id = 2

    class FakeProject:
        id = 2
        owner_id = 1

    class FakeSession:
        async def execute(self, stmt):
            model = stmt.column_descriptions[0]["entity"]
            if model is UsersBase:
                class Result:
                    def scalar_one_or_none(self): return FakeUser()
                return Result()
            else:
                class Result:
                    def scalar_one_or_none(self): return FakeProject()
                return Result()
        async def delete(self, obj): pass
        async def commit(self): pass

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.delete("/users/1")

    assert response.status_code == 204

    application.dependency_overrides.clear()
