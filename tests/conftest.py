# tests/conftest.py
import fastapi
import pytest
from fastapi.testclient import TestClient
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# ── 2) Путь до папки backend/ ─────────────────────────────────────────────
BACKEND_ROOT = os.path.join(PROJECT_ROOT, "backend")

# Пишем их в sys.path в нужном порядке:
for p in (BACKEND_ROOT, PROJECT_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest
from fastapi.testclient import TestClient
from backend.app.main import application  # теперь Python найдёт пакет app

@pytest.fixture(scope="session")
def client():
    with TestClient(application) as c:
        yield c

# Assuming your FastAPI app object is named `application` in app/main.py
client = TestClient(application)

