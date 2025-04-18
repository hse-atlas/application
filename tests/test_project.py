import pytest
from fastapi.testclient import TestClient
from backend.app.main import application
from app.admin_auth import get_current_admin
from app.project_CRUD import get_async_session
from app.schemas import ProjectOAuthSettings

BASE = "/api/v1/AuthService/api/v1/AuthService"

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

# -------------------- Project CRUD tests --------------------

@pytest.mark.asyncio
async def test_create_project_success(monkeypatch, client):
    payload = {
        "name": "Test Project",
        "description": "Some description",
        "url": "https://example.com",
        "oauth_enabled": False,
        "oauth_providers": {
            "google": {
                "client_id": "id",
                "client_secret": "secret",
                "redirect_uri": "https://ex.com",
                "enabled": True
            },
            "enabled": False
        }
    }

    async def fake_get_current_admin():
        return FakeAdmin()

    class FakeSession:
        def add(self, x): pass
        async def commit(self): pass
        async def refresh(self, obj): obj.id = 1

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.post("/projects/", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert data["id"] == 1
    assert data["name"] == payload["name"]

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_update_project_forbidden(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=999)

    class FakeProject:
        id = 1
        name = "Test"
        description = "Desc"
        owner_id = 1
        url = "url"
        oauth_enabled = False

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def scalar_one_or_none(self):
                    return FakeProject()
            return Result()
        async def commit(self): pass
        async def refresh(self, x): pass

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    payload = {"name": "Updated"}
    client.cookies.set("users_access_token", "token")
    response = client.put("/projects/owner/1", json=payload)

    assert response.status_code == 403
    assert "Нет прав" in response.json()["detail"]

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_get_project_url_success(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeProject:
        id = 1
        owner_id = 1
        url = "https://project.com"

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def scalar_one_or_none(self):
                    return FakeProject()
            return Result()

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.get("/projects/getURL/1")

    assert response.status_code == 200
    assert response.json() == "https://project.com"

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_delete_project_success(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeProject:
        id = 1
        owner_id = 1

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def scalar_one_or_none(self):
                    return FakeProject()
            return Result()
        async def delete(self, x): pass
        async def commit(self): pass

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.delete("/projects/owner/1")

    assert response.status_code == 204

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_list_admin_projects(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeRow:
        def __init__(self):
            self.id = 1
            self.name = "Test"
            self.description = "Desc"
            self.owner_id = 1
            self.url = "url"
            self.oauth_enabled = False
            self.user_count = 5

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def all(self):
                    return [FakeRow()]
            return Result()

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.get("/projects/owner")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert response.json()[0]["name"] == "Test"

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_update_project_oauth(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeProject:
        id = 1
        name = "Test"
        description = "Desc"
        owner_id = 1
        url = "url"
        oauth_enabled = False

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def scalar_one_or_none(self): return FakeProject()
                def scalar(self): return 0  # For counting users
            return Result()
        async def commit(self): pass
        async def refresh(self, obj): pass

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    payload = {
        "enabled": True,
        "google": {
            "client_id": "id",
            "client_secret": "secret",
            "redirect_uri": "https://ex.com",
            "enabled": True
        }
    }

    client.cookies.set("users_access_token", "token")
    response = client.put("/projects/1/oauth", json=payload)

    assert response.status_code == 200
    assert response.json()["id"] == 1

    application.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_get_project_details(monkeypatch, client):
    async def fake_get_current_admin():
        return FakeAdmin(id=1)

    class FakeRow:
        def __init__(self):
            self.id = 1
            self.name = "Test"
            self.description = "Desc"
            self.owner_id = 1
            self.url = "url"
            self.oauth_enabled = False
            self.oauth_providers = None
            self.user_count = 1

    class FakeUser:
        id = 1
        login = "user"
        email = "user@example.com"
        role = "user"
        oauth_provider = None

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def first(self): return FakeRow()
                def all(self): return [FakeUser()]
            return Result()

    application.dependency_overrides[get_current_admin] = fake_get_current_admin
    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    client.cookies.set("users_access_token", "token")
    response = client.get("/projects/1")

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test"
    assert data["users"][0]["login"] == "user"

    application.dependency_overrides.clear()
