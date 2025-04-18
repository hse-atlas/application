import pytest
from fastapi.testclient import TestClient
from backend.app.main import application
import app.oauth
from app.oauth import get_async_session
from fastapi.responses import RedirectResponse

BASE = "/oauth"

@pytest.fixture(scope="module")
def client():
    return TestClient(application)

@pytest.fixture(autouse=True)
def override_redis(monkeypatch):
    class FakeRedis:
        async def setex(self, *a, **kw): pass
    monkeypatch.setattr("app.jwt_auth.redis_client", FakeRedis())

@pytest.fixture(autouse=True)
def fake_oauth_config(monkeypatch):
    monkeypatch.setitem(
        app.oauth.OAUTH_PROVIDERS,
        "google",
        {
            "client_id": "test-client-id",
            "client_secret": "test-secret",
            "redirect_uri": "https://test-redirect",
            "scope": "email",
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "v": "5.131"
        }
    )

@pytest.fixture(autouse=True)
def override_get_async_session(monkeypatch):
    class FakeProject:
        id = 99999
        name = "Mock Project"
        description = "Test"
        oauth_enabled = True
        oauth_providers = {"google": {"enabled": True}}
        owner_id = 1

    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def scalar_one_or_none(self):
                    return None if "notfound" in str(stmt) else FakeProject()
            return Result()
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass

    monkeypatch.setattr("app.oauth.get_async_session", lambda: FakeSession())

# -------------------- OAuth Tests --------------------

def test_admin_oauth_login_redirect(client):
    response = client.get(f"{BASE}/admin/google")
    assert response.status_code in (302, 307)
    assert "https://" in response.headers["location"]
    assert "client_id" in response.headers["location"]
    assert "state=" in response.headers["location"]

def test_user_oauth_login_invalid_project(client):
    class FakeSession:
        async def execute(self, stmt):
            class Result:
                def scalar_one_or_none(self): return None
            return Result()
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass

    application.dependency_overrides[get_async_session] = lambda: FakeSession()

    response = client.get(f"{BASE}/user/google/99999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Project not found"

    application.dependency_overrides.clear()

def test_oauth_provider_not_supported(client):
    response = client.get(f"{BASE}/admin/unknown_provider")
    assert response.status_code == 404
    assert response.json()["detail"] == "OAuth provider unknown_provider not supported"

# -------------------- Callback Placeholder --------------------

def test_google_callback_state_mismatch(client):
    with client.session_transaction() as session:
        session["oauth_state"] = "correct_state"
    
    response = client.get("/oauth/google/callback?code=abc123&state=wrong_state")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid state parameter"
