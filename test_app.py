import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import sys
sys.path.insert(0, '.')

from app import app, get_db

client = TestClient(app)

# Test DB setup (runs in memory)
@pytest.fixture(autouse=True)
def setup_db():
    # Clear test data between tests
    pass
import pytest
from fastapi.testclient import TestClient
from app import app, Base, DBEmployee, get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import shutil

# Test database
TEST_DB_URL = "sqlite:///./test_employees.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Create test tables
Base.metadata.create_all(bind=test_engine)

client = TestClient(app)

def override_get_db():
    test_db = TestingSessionLocal()
    try:
        yield test_db
    finally:
        test_db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def cleanup():
    yield
    # Cleanup test data
    with test_engine.connect() as conn:
        conn.execute(DBEmployee.__table__.delete())
        conn.commit()

def get_token():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert response.status_code == 200
    return response.json()["access_token"]

class TestEmployeeAPI:
    def test_root(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "Employee Management API" in response.json()["message"]

    def test_login_success(self):
        response = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_login_fail(self):
        response = client.post("/api/auth/login", json={"username": "wrong", "password": "wrong"})
        assert response.status_code == 401

    def test_create_employee(self):
        token = get_token()
        response = client.post("/api/employees/",
                              headers={"Authorization": f"Bearer {token}"},
                              json={"name": "John Doe", "email": "john@company.com", "department": "HR"})
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "John Doe"
        assert data["email"] == "john@company.com"
        assert "id" in data

    def test_duplicate_email(self):
        token = get_token()
        # Create first
        client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                   json={"name": "First", "email": "dup@company.com"})
        # Duplicate fails
        response = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                              json={"name": "Duplicate", "email": "dup@company.com"})
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]

    def test_list_employees(self):
        token = get_token()
        # Create test data
        client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                   json={"name": "HR User", "email": "hr@company.com", "department": "HR"})
        response = client.get("/api/employees/?department=HR", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        employees = response.json()
        assert len(employees) > 0
        assert employees[0]["department"] == "HR"

    def test_get_employee(self):
        token = get_token()
        create_resp = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                                 json={"name": "Get Test", "email": "get@company.com"})
        emp_id = create_resp.json()["id"]
        response = client.get(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    def test_get_employee_404(self):
        token = get_token()
        response = client.get("/api/employees/999/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 404

    def test_update_employee(self):
        token = get_token()
        create_resp = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                                 json={"name": "Update Me", "email": "update@company.com"})
        emp_id = create_resp.json()["id"]
        
        response = client.put(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"},
                             json={"department": "Sales", "role": "Manager"})
        assert response.status_code == 200
        assert response.json()["department"] == "Sales"

    def test_delete_employee(self):
        token = get_token()
        create_resp = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                                 json={"name": "Delete Me", "email": "delete@company.com"})
        emp_id = create_resp.json()["id"]
        
        response = client.delete(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 204
        
        # Verify gone
        final_check = client.get(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"})
        assert final_check.status_code == 404

def get_token():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "secret"})
    assert response.status_code == 200
    return response.json()["access_token"]

def test_create_employee():
    token = get_token()
    response = client.post("/api/employees/", 
                          headers={"Authorization": f"Bearer {token}"},
                          json={"name": "John Doe", "email": "john@example.com", "department": "HR"})
    assert response.status_code == 201
    assert response.json()["name"] == "John Doe"

def test_duplicate_email():
    token = get_token()
    # First create succeeds
    client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
               json={"name": "First", "email": "dup@example.com"})
    # Second fails
    response = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                          json={"name": "Duplicate", "email": "dup@example.com"})
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]

def test_list_employees_filter():
    token = get_token()
    client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
               json={"name": "HR Test", "email": "hr@test.com", "department": "HR"})
    response = client.get("/api/employees/?department=HR", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    employees = response.json()
    assert len(employees) > 0
    assert any(e["department"] == "HR" for e in employees)

def test_get_employee_404():
    token = get_token()
    response = client.get("/api/employees/999/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404

def test_update_employee():
    token = get_token()
    create_resp = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                             json={"name": "Update Me", "email": "update@test.com"})
    emp_id = create_resp.json()["id"]
    
    update_resp = client.put(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"},
                            json={"department": "Sales"})
    assert update_resp.status_code == 200
    assert update_resp.json()["department"] == "Sales"

def test_delete_employee():
    token = get_token()
    create_resp = client.post("/api/employees/", headers={"Authorization": f"Bearer {token}"},
                             json={"name": "Delete Me", "email": "delete@test.com"})
    emp_id = create_resp.json()["id"]
    
    delete_resp = client.delete(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"})
    assert delete_resp.status_code == 204
    
    # Verify deleted
    get_resp = client.get(f"/api/employees/{emp_id}/", headers={"Authorization": f"Bearer {token}"})
    assert get_resp.status_code == 404
