# FastAPI JWT Authentication Microservice

A secure REST API authentication system built using **FastAPI, Python, SQLAlchemy, SQLite and JWT**.

## Project Overview

This project provides user authentication and account management through JSON Web Tokens (JWT). It supports access tokens, refresh tokens, secure logout, password management and token revocation.

## Features

- User registration and login
- Password hashing using bcrypt
- JWT access and refresh tokens
- Token expiration and validation
- Secure logout and token revocation
- User profile retrieval and updates
- Account deactivation
- Password change functionality
- Token versioning for multi-session invalidation
- Environment variable configuration
- SQLite database integration

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| FastAPI | REST API framework |
| SQLite | Database |
| SQLAlchemy | ORM |
| JWT | Authentication |
| bcrypt | Password hashing |
| Pydantic | Data validation |
| Uvicorn | ASGI server |

## Project Structure

```text
FastAPI_JWT_Project/
│
├── app/
│   ├── routers/
│   │   └── auth.py
│   ├── schemas/
│   │   └── user.py
│   ├── models/
│   │   ├── user.py
│   │   └── revoked_token.py
│   ├── utils/
│   │   └── security.py
│   ├── dependencies.py
│   ├── database.py
│   └── main.py
│
├── .env
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd FastAPI_JWT_Project
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Create a `.env` file in the project root.

Configure the following variables:

```env
SECRET_KEY=YOUR_STRONG_PRIVATE_SECRET_KEY
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

Generate a strong secret key and never upload your real `.env` file to GitHub.

### 6. Run the application

```bash
uvicorn app.main:app --reload
```

### 7. Open Swagger documentation

Visit:

http://127.0.0.1:8000/docs

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/register` | Register a user |
| POST | `/auth/login` | User login |
| GET | `/auth/me` | Get current user |
| PUT | `/auth/me` | Update user profile |
| DELETE | `/auth/me` | Deactivate account |
| POST | `/auth/change-password` | Change password |
| POST | `/auth/logout` | Logout and revoke tokens |
| POST | `/auth/refresh` | Refresh JWT tokens |

## Security Features

- Passwords are hashed before database storage.
- Access and refresh tokens have separate expiration periods.
- Revoked tokens are rejected.
- Password changes increment the user's token version.
- Old tokens from previous sessions are rejected.
- Inactive accounts cannot authenticate.
- Sensitive configuration is stored in environment variables.

## Testing

The API was tested using FastAPI Swagger UI.

Tested functionality includes:

- User registration and login
- Access token authentication
- Refresh token generation
- Profile updates
- Secure logout
- Token revocation
- Password changes
- Multi-session token invalidation
- Account deactivation

## Future Improvements

- Automated unit and integration tests
- PostgreSQL database integration
- Email verification
- Password reset functionality
- Docker deployment
- Cloud deployment

## Author

**DHEEPAN P.**

B.Tech – Artificial Intelligence and Data Science

Sri Krishna College of Engineering and Technology

---

*This project was developed as a backend development and authentication learning project.*