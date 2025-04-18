import pytest
from fastapi.testclient import TestClient
from backend.app.main import application
from app.admin_auth import get_current_admin  # Добавлено для переопределения Depends

# Двойной префикс, применённый в коде:
BASE = "/api/v1/AuthService/api/v1/AuthService"

# Фейковый класс администратора для моков
class FakeAdmin:
    def __init__(self, id=1, login="admin", email="admin@example.com", password="hashedpwd"):
        self.id = id
        self.login = login
        self.email = email
        self.password = password

@pytest.fixture(scope="module")
def client():
    return TestClient(application)

# -------------------- Tests for /register/ --------------------

@pytest.mark.asyncio
async def test_register_success(monkeypatch, client):
    payload = {"email": "new@admin.com", "password": "Aa1!aaaa", "login": "newadmin"}

    async def fake_find(**kwargs):
        return None
    async def fake_add(**kwargs):
        return FakeAdmin(id=42, login=kwargs["login"], email=kwargs["email"])

    monkeypatch.setattr("app.core.find_one_or_none_admin", fake_find)
    monkeypatch.setattr("app.core.add_admin", fake_add)
    monkeypatch.setattr("app.admin_auth.password_meets_requirements", lambda pwd: (True, None))
    monkeypatch.setattr("app.admin_auth.get_password_hash", lambda pwd: "hashed")

    response = client.post(f"{BASE}/register/", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["message"] == "Registration completed successfully!"
    assert data["admin_id"] == 42

@pytest.mark.asyncio
async def test_register_conflict_email(monkeypatch, client):
    payload = {"email": "existing@admin.com", "password": "Aa1!aaaa", "login": "newadmin"}

    async def fake_find(**kwargs):
        if kwargs.get("email") == payload["email"]:
            return FakeAdmin()
        return None

    monkeypatch.setattr("app.core.find_one_or_none_admin", fake_find)
    monkeypatch.setattr("app.admin_auth.password_meets_requirements", lambda pwd: (True, None))

    response = client.post(f"{BASE}/register/", json=payload)
    assert response.status_code == 409
    assert "E-mail already registered" in response.json()["detail"]

@pytest.mark.asyncio
async def test_register_conflict_login(monkeypatch, client):
    payload = {"email": "new@admin.com", "password": "Aa1!aaaa", "login": "existlogin"}

    async def fake_find(**kwargs):
        if kwargs.get("login") == payload["login"]:
            return FakeAdmin()
        return None

    monkeypatch.setattr("app.core.find_one_or_none_admin", fake_find)
    monkeypatch.setattr("app.admin_auth.password_meets_requirements", lambda pwd: (True, None))

    response = client.post(f"{BASE}/register/", json=payload)
    assert response.status_code == 409
    assert "Login already exists" in response.json()["detail"]

# -------------------- Tests for /login/ --------------------

@pytest.mark.asyncio
async def test_login_invalid_email(monkeypatch, client):
    payload = {"email": "no@admin.com", "password": "Pass1!"}

    async def fake_find(**kwargs):
        return None

    monkeypatch.setattr("app.core.find_one_or_none_admin", fake_find)

    response = client.post(f"{BASE}/login/", json=payload)
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_invalid_password(monkeypatch, client):
    payload = {"email": "admin@ex.com", "password": "Wrong1!"}

    async def fake_find(**kwargs):
        return FakeAdmin(password="hashedpwd")

    monkeypatch.setattr("app.core.find_one_or_none_admin", fake_find)
    monkeypatch.setattr("app.admin_auth.verify_password", lambda plain, hashed: False)

    response = client.post(f"{BASE}/login/", json=payload)
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_success(monkeypatch, client):
    payload = {"email": "admin@ex.com", "password": "Right1!"}

    async def fake_find(**kwargs):
        return FakeAdmin(id=7)

    async def fake_create_access_token(data):
        return "acc_token"

    async def fake_create_refresh_token(data):
        return "ref_token"

    monkeypatch.setattr("app.core.find_one_or_none_admin", fake_find)
    monkeypatch.setattr("app.admin_auth.verify_password", lambda plain, hashed: True)
    monkeypatch.setattr("app.jwt_auth.create_access_token", fake_create_access_token)
    monkeypatch.setattr("app.jwt_auth.create_refresh_token", fake_create_refresh_token)

    response = client.post(f"{BASE}/login/", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] == "acc_token"
    assert body["refresh_token"] == "ref_token"
    assert response.cookies.get("admins_access_token") == "acc_token"
    assert response.cookies.get("admins_refresh_token") == "ref_token"

# -------------------- Tests for /refresh/ --------------------

@pytest.mark.asyncio
async def test_refresh_missing_token(client):
    response = client.post(f"{BASE}/refresh/")
    assert response.status_code == 400
    assert "Refresh token not provided" in response.json()["detail"]

@pytest.mark.asyncio
async def test_refresh_success(monkeypatch, client):
    payload = {"refresh_token": "old_ref"}

    async def fake_refresh(token, db=None):
        return {"access_token": "new_acc", "refresh_token": "new_ref"}

    monkeypatch.setattr("app.admin_auth.refresh_tokens", fake_refresh)

    client.cookies.set("admins_refresh_token", "old_ref")
    response = client.post(f"{BASE}/refresh/", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] == "new_acc"
    assert body["refresh_token"] == "new_ref"
    assert response.cookies.get("users_access_token") == "new_acc"
    assert response.cookies.get("users_refresh_token") == "new_ref"

# -------------------- Tests for /me --------------------

@pytest.mark.asyncio
async def test_get_admin_profile(client):
    async def fake_get_current_admin():
        return FakeAdmin(login="meadmin", email="me@ex.com")

    application.dependency_overrides[get_current_admin] = fake_get_current_admin

    client.cookies.set("users_access_token", "token")
    response = client.get(f"{BASE}/me")
    assert response.status_code == 200
    data = response.json()
    assert data == {"login": "meadmin", "email": "me@ex.com", "user_role": "admin"}

    application.dependency_overrides.clear()

# -------------------- Tests for user_register and user_login --------------------

@pytest.mark.asyncio
async def test_user_register_success(monkeypatch, client):
    from app.core import find_one_or_none_user, add_user

    project_id = 1
    payload = {"email": "test@user.com", "password": "Aa1!aaaa", "login": "newuser"}

    async def fake_find_user(**kwargs):
        return None

    async def fake_add_user(**kwargs):
        class User:
            id = 101
        return User()

    monkeypatch.setattr("app.core.find_one_or_none_user", fake_find_user)
    monkeypatch.setattr("app.core.add_user", fake_add_user)
    monkeypatch.setattr("app.user_auth.password_meets_requirements", lambda pwd: (True, None))
    monkeypatch.setattr("app.user_auth.get_password_hash", lambda pwd: "hashed")

    response = client.post(f"{BASE}/user_register/{project_id}", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["message"]
    assert data["user_id"] == 101

@pytest.mark.asyncio
async def test_user_login_success(monkeypatch, client):
    project_id = 1
    payload = {"email": "test@user.com", "password": "Aa1!aaaa"}

    class User:
        id = 7
        email = payload["email"]
        password = "hashedpwd"

    async def fake_execute(query):
        class Result:
            def scalar_one_or_none(self):
                return User()
        return Result()

    monkeypatch.setattr("sqlalchemy.ext.asyncio.AsyncSession.execute", fake_execute)
    monkeypatch.setattr("app.user_auth.verify_password", lambda plain, hashed: True)
    monkeypatch.setattr("app.jwt_auth.create_access_token", lambda data: "token1")
    monkeypatch.setattr("app.jwt_auth.create_refresh_token", lambda data: "token2")

    response = client.post(f"{BASE}/user_login/{project_id}", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "token1"
    assert data["refresh_token"] == "token2"
