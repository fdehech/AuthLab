# AuthLab 🛡️

AuthLab is a high-performance, secure authentication microservice built with **FastAPI**, **SQLAlchemy**, and **Redis**. It provides a robust foundation for managing user sessions, implementing JWT-based authentication, and protecting APIs with advanced security features.

[![CI](https://github.com/fdehech/AuthLab/actions/workflows/ci.yml/badge.svg)](https://github.com/fdehech/AuthLab/actions/workflows/ci.yml)

## 🚀 Features

- **JWT Authentication**: Secure access token generation using `python-jose`.
- **Refresh Token Rotation**: Implements single-use refresh tokens for enhanced security against session hijacking.
- **Multi-Device Session Management**: Track and revoke all active sessions for a user (e.g., after a password change).
- **Rate Limiting**: Built-in protection against brute-force attacks on the login endpoint using Redis.
- **Role-Based Access Control (RBAC)**: Flexible middleware to restrict access to specific endpoints based on user roles (`user`, `admin`).
- **Database Persistence**: User data stored securely in SQLite (via SQLAlchemy).
- **Redis Integration**: High-speed session management and rate limiting.
- **CI/CD Ready**: Integrated with GitHub Actions for automated testing and linting.

## 🛠️ Tech Stack

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/)
- **ORM**: [SQLAlchemy](https://www.sqlalchemy.org/)
- **Security**: [python-jose](https://github.com/mpdavis/python-jose) (JWT), [Passlib](https://passlib.readthedocs.io/) (Bcrypt)
- **Data Store**: [Redis](https://redis.io/) & SQLite
- **Testing**: [Pytest](https://docs.pytest.org/) & [HTTPX](https://www.python-httpx.org/)
- **Linting**: [Ruff](https://github.com/astral-sh/ruff) & [Black](https://github.com/psf/black)

## 📁 Project Structure

```text
AuthLab/
├── app/
│   ├── models/          # Data Models (Pydantic & SQLAlchemy)
│   │   ├── __init__.py  # Exports for easy access
│   │   ├── requests.py  # Pydantic request/response models
│   │   └── sql.py       # SQLAlchemy database models
│   ├── routes/          # API Endpoints (auth, user)
│   ├── auth.py          # Authentication logic & JWT utilities
│   ├── config.py        # Configuration & Redis setup
│   ├── db.py            # Database connection & session
│   └── __init__.py
├── tests/               # Comprehensive test suite
├── .github/workflows/   # CI/CD pipeline (GitHub Actions)
├── main.py              # Application entry point
├── requirements.txt     # Project dependencies
└── .env                 # Environment variables
```

## ⚙️ Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/fdehech/AuthLab.git
cd AuthLab
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file in the root directory:
```env
REDIS_URL=redis://localhost:6379
MASTER_SECRET=your_super_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_MINUTES=30
REFRESH_TOKEN_DAYS=7
LOGIN_LIMIT=5
LOGIN_WINDOW_SECONDS=60
```

### 5. Run the Application
```bash
python main.py
```
The API will be available at `http://localhost:8000`.

### 6. Run Tests & Linting
```bash
# Run all tests
python -m pytest

# Run linting checks
ruff check .

# Format code
black .
```

## 📖 API Documentation

Once the server is running, you can access the interactive API documentation:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints:
- `POST /register`: Create a new user account with a specific role.
- `POST /login`: Authenticate and receive JWT tokens.
- `POST /refresh`: Rotate refresh tokens and get a new access token.
- `POST /logout`: Invalidate a specific refresh token.
- `POST /change-password`: Update password and revoke all active sessions.
- `GET /me`: Get current user profile (Protected).
- `GET /admin`: Access admin-only resources (Protected).

## 🔒 Security Implementation

- **Token Rotation**: Every time a refresh token is used, it is invalidated and a new one is issued.
- **Session Revocation**: Changing a password automatically invalidates all active refresh tokens across all devices.
- **Rate Limiting**: Login attempts are tracked by IP address in Redis. If the limit is exceeded, the user is blocked for a configurable window.
- **Password Hashing**: Secure password storage using Bcrypt with a high work factor.

## 📝 License

This project is licensed under the MIT License.
