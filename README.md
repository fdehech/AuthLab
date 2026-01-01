# AuthLab 🛡️

AuthLab is a high-performance, secure authentication microservice built with **FastAPI** and **Redis**. It provides a robust foundation for managing user sessions, implementing JWT-based authentication, and protecting APIs with advanced security features.

## 🚀 Features

- **JWT Authentication**: Secure access token generation using `python-jose`.
- **Refresh Token Rotation**: Implements single-use refresh tokens for enhanced security against session hijacking.
- **Rate Limiting**: Built-in protection against brute-force attacks on the login endpoint using Redis.
- **Role-Based Access Control (RBAC)**: Flexible middleware to restrict access to specific endpoints based on user roles.
- **Redis Integration**: High-speed session management and rate limiting.
- **Clean Architecture**: Modular structure for easy maintenance and scalability.

## 🛠️ Tech Stack

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/)
- **ORM**: [SQLAlchemy](https://www.sqlalchemy.org/)
- **Security**: [python-jose](https://github.com/mpdavis/python-jose) (JWT), [Passlib](https://passlib.readthedocs.io/) (Bcrypt)
- **Data Store**: [Redis](https://redis.io/) & SQLite
- **Server**: [Uvicorn](https://www.uvicorn.org/)
- **Validation**: [Pydantic](https://docs.pydantic.dev/)

## 📁 Project Structure

```text
AuthLab/
├── app/
│   ├── models/          # Data Models
│   │   ├── __init__.py  # Exports for easy access
│   │   ├── requests.py  # Pydantic request/response models
│   │   └── sql.py       # SQLAlchemy database models
│   ├── routes/          # API Endpoints (auth, user)
│   ├── auth.py          # Authentication logic & JWT utilities
│   ├── config.py        # Configuration & Redis setup
│   ├── db.py            # Database connection & session
│   └── __init__.py
├── main.py              # Application entry point
├── requirements.txt     # Project dependencies
└── .env                 # Environment variables
```

## ⚙️ Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/AuthLab.git
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

## 📖 API Documentation

Once the server is running, you can access the interactive API documentation:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints:
- `POST /register`: Create a new user account.
- `POST /login`: Authenticate and receive JWT tokens.
- `POST /refresh`: Rotate refresh tokens and get a new access token.
- `POST /logout`: Invalidate a refresh token.

## 🔒 Security Implementation

- **Token Rotation**: Every time a refresh token is used, it is invalidated and a new one is issued.
- **Rate Limiting**: Login attempts are tracked by IP address in Redis. If the limit is exceeded, the user is blocked for a configurable window.
- **Password Hashing**: (Planned/Implemented) Secure password storage using Bcrypt.

## 📝 License

This project is licensed under the MIT License.
