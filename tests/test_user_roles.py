import pytest
from fastapi.testclient import TestClient
from backend.app.main import application
from app.user_roles import get_async_session, get_current_admin

BASE = "/projects"

@pytest.fixture(scope="module")
def client():
    return TestClient(application)

@pytest.fixture(autouse=True)
def override_dependencies(monkeypatch):
    class FakeAdmin:
        id = 1
        email = "admin@example.com"

    class FakeUser:
        id = 1
        login = "user"
        email = "user@example.com"
        role = "user"
        project_id = 1

    class FakeProject:
        id = 1
        owner_id = 1

    class FakeSession:
        async def execute(self, stmt):
            stmt_str = str(stmt)
            class Result:
                def scalar_one_or_none(inner_self):
                    if "UsersBase" in stmt_str and "project_id =" in stmt_str:
                        return FakeUser()
                    if "ProjectsBase" in stmt_str:
                        return FakeProject()
                    return None
            return Result()
        async def commit(self): pass
        async def refresh(self, obj): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass

    monkeypatch.setattr("app.user_roles.get_current_admin", lambda: FakeAdmin())
    monkeypatch.setattr("app.user_roles.get_async_session", lambda: FakeSession())
    monkeypatch.setattr("app.jwt_auth.auth_middleware", lambda request, session: True)

# -------------------- User Role Tests --------------------

def test_get_user_role(client):
    client.cookies.set("admins_access_token", "fake-token")
    response = client.get(f"{BASE}/1/users/1/role")
    assert response.status_code == 200
    assert response.json() == {"user_id": 1, "role": "user"}

def test_update_user_role(client):
    client.cookies.set("admins_access_token", "fake-token")
    payload = {"new_role": "admin"}
    response = client.put(f"{BASE}/1/users/1/role", json=payload)
    assert response.status_code == 200
    assert "updated to admin" in response.json()["message"]

def test_update_user_role_invalid_role(client):
    client.cookies.set("admins_access_token", "fake-token")
    payload = {"new_role": "superadmin"}
    response = client.put(f"{BASE}/1/users/1/role", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"] == "Role must be 'user' or 'admin'"
