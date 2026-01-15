# Employee Management REST API

A RESTful API built using FastAPI to manage employees in a company.
The API supports CRUD operations, JWT-based authentication, filtering, pagination, and unit testing.

---

##  Features

* Token-based authentication (JWT)
* Create, Read, Update, Delete (CRUD) employee records
* Email validation and uniqueness check
* Filtering by department and role
* Pagination support
* Proper HTTP status codes and error handling
* Interactive API documentation using Swagger
* Unit tests using Pytest

---

##  Tech Stack

* Backend Framework: FastAPI
* Database: SQLite
* ORM: SQLAlchemy
* Authentication: JWT (python-jose)
* Password Hashing: bcrypt (native)
* Testing: Pytest
* Deployment: Render

---

##  Project Structure

```
Employee_management/
│
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
└── test_app.py
```

---

##  Environment Variables

Create a `.env` file (not committed to GitHub) using the following format:

```
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./employees.db
```

Refer to `.env.example` for reference.

---

##  Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/AanLetna7025/employee-management-api.git
cd employee-management-api
```

### 2. Create and activate virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the server

```bash
uvicorn app:app --reload
```

### 5. Open Swagger UI

```
http://127.0.0.1:8000/docs
```

---

##  Authentication

### Login to get JWT token

**POST** `/api/auth/login`

```json
{
  "username": "admin",
  "password": "secret"
}
```

Use the returned token in request headers:

```
Authorization: Bearer <your_token>
```

---

##  API Endpoints

| Method | Endpoint             | Description       |
| ------ | -------------------- | ----------------- |
| POST   | /api/auth/login      | Get JWT token     |
| POST   | /api/employees/      | Create employee   |
| GET    | /api/employees/      | List employees    |
| GET    | /api/employees/{id}/ | Retrieve employee |
| PUT    | /api/employees/{id}/ | Update employee   |
| DELETE | /api/employees/{id}/ | Delete employee   |

---

##  Filtering & Pagination

Examples:

```
GET /api/employees/?department=HR
GET /api/employees/?role=Developer
GET /api/employees/?page=2
```

* Pagination limit: **10 employees per page**

---

##  Error Handling

| Status Code | Meaning                            |
| ----------- | ---------------------------------- |
| 201         | Employee created                   |
| 400         | Validation error / duplicate email |
| 401         | Unauthorized                       |
| 404         | Employee not found                 |
| 204         | Employee deleted successfully      |

---

##  Testing

Run unit tests using:

```bash
pytest
```

Tests cover:

* Authentication
* Employee creation
* Duplicate email validation
* Fetching employee by ID
* 404 error handling
* Filtering employees

---

##  Live Demo

Swagger UI (Hosted on Render):

```
https://employee-management-api.onrender.com/docs
```

---

## Conclusion

This project demonstrates:

* Proper RESTful API design
* Secure authentication
* Clean code organization
* Error handling best practices
* API testing and documentation
=======

