
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from datetime import datetime, timezone
import bcrypt

from app.database import get_db
from app.models.user import User
from app.models.revoked_token import RevokedToken

from app.dependencies import get_current_user

from app.schemas.user import (
    UserCreate,
    UserResponse,
    UserLogin,
    TokenResponse,
    RefreshTokenRequest,
    UserUpdate,
    ChangePassword
)

from app.utils.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

security = HTTPBearer()


# ---------------------------------
# USER REGISTRATION
# ---------------------------------

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    existing_username = db.query(User).filter(
        User.username == user.username
    ).first()

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    existing_email = db.query(User).filter(
        User.email == user.email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    hashed_password = bcrypt.hashpw(
        user.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


# ---------------------------------
# USER LOGIN
# ---------------------------------

@router.post(
    "/login",
    response_model=TokenResponse
)
def login_user(
    user: UserLogin,
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not verify_password(
        user.password,
        existing_user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not existing_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )

    token_data = {
        "sub": str(existing_user.id),
        "token_version": existing_user.token_version
    }

    return {
        "access_token": create_access_token(data=token_data),
        "refresh_token": create_refresh_token(data=token_data),
        "token_type": "bearer"
    }


# ---------------------------------
# GET CURRENT USER PROFILE
# ---------------------------------

@router.get(
    "/me",
    response_model=UserResponse
)
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return current_user


# ---------------------------------
# UPDATE USER PROFILE
# ---------------------------------

@router.put(
    "/me",
    response_model=UserResponse
)
def update_my_profile(
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing_user = db.query(User).filter(
        User.username == user_data.username,
        User.id != current_user.id
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    current_user.username = user_data.username

    db.commit()
    db.refresh(current_user)

    return current_user


# ---------------------------------
# DEACTIVATE USER ACCOUNT
# ---------------------------------

@router.delete("/me")
def deactivate_my_account(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    access_payload = decode_access_token(
        credentials.credentials
    )

    if access_payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token"
        )

    current_user.is_active = False
    current_user.token_version += 1

    db.add(
        RevokedToken(
            jti=access_payload["jti"],
            expires_at=datetime.fromtimestamp(
                access_payload["exp"],
                tz=timezone.utc
            )
        )
    )

    db.commit()

    return {
        "message": "Account deactivated successfully"
    }


# ---------------------------------
# CHANGE PASSWORD
# ---------------------------------

@router.post("/change-password")
def change_password(
    request: ChangePassword,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    access_payload = decode_access_token(
        credentials.credentials
    )

    refresh_payload = decode_refresh_token(
        request.refresh_token
    )

    if access_payload is None or refresh_payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    if (
        access_payload.get("sub") != str(current_user.id)
        or refresh_payload.get("sub") != str(current_user.id)
    ):
        raise HTTPException(
            status_code=401,
            detail="Tokens do not belong to the same user"
        )

    if (
        access_payload.get("token_version") != current_user.token_version
        or refresh_payload.get("token_version") != current_user.token_version
    ):
        raise HTTPException(
            status_code=401,
            detail="Token version is invalid"
        )

    refresh_jti = refresh_payload.get("jti")

    if not refresh_jti:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    existing_revocation = db.query(RevokedToken).filter(
        RevokedToken.jti == refresh_jti
    ).first()

    if existing_revocation:
        raise HTTPException(
            status_code=401,
            detail="Refresh token has been revoked"
        )

    if not verify_password(
        request.current_password,
        current_user.hashed_password
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )

    if verify_password(
        request.new_password,
        current_user.hashed_password
    ):
        raise HTTPException(
            status_code=400,
            detail="New password must be different"
        )

    current_user.hashed_password = bcrypt.hashpw(
        request.new_password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Invalidate all previously issued tokens
    current_user.token_version += 1

    tokens_to_revoke = [
        access_payload,
        refresh_payload
    ]

    for payload in tokens_to_revoke:
        existing = db.query(RevokedToken).filter(
            RevokedToken.jti == payload["jti"]
        ).first()

        if not existing:
            db.add(
                RevokedToken(
                    jti=payload["jti"],
                    expires_at=datetime.fromtimestamp(
                        payload["exp"],
                        tz=timezone.utc
                    )
                )
            )

    db.commit()

    return {
        "message": "Password changed successfully. Please log in again."
    }


# ---------------------------------
# USER LOGOUT
# ---------------------------------

@router.post("/logout")
def logout_user(
    request: RefreshTokenRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    access_payload = decode_access_token(
        credentials.credentials
    )

    refresh_payload = decode_refresh_token(
        request.refresh_token
    )

    if access_payload is None or refresh_payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    if (
        access_payload.get("sub") != str(current_user.id)
        or refresh_payload.get("sub") != str(current_user.id)
    ):
        raise HTTPException(
            status_code=401,
            detail="Tokens do not belong to the same user"
        )

    for payload in [access_payload, refresh_payload]:
        existing = db.query(RevokedToken).filter(
            RevokedToken.jti == payload["jti"]
        ).first()

        if not existing:
            db.add(
                RevokedToken(
                    jti=payload["jti"],
                    expires_at=datetime.fromtimestamp(
                        payload["exp"],
                        tz=timezone.utc
                    )
                )
            )

    db.commit()

    return {
        "message": "Successfully logged out"
    }


# ---------------------------------
# REFRESH ACCESS TOKEN
# ---------------------------------

@router.post(
    "/refresh",
    response_model=TokenResponse
)
def refresh_access_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    payload = decode_refresh_token(
        request.refresh_token
    )

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired refresh token"
        )

    jti = payload.get("jti")

    if not jti:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    revoked_token = db.query(RevokedToken).filter(
        RevokedToken.jti == jti
    ).first()

    if revoked_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token has been revoked"
        )

    try:
        user_id = int(payload.get("sub"))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload"
        )

    current_user = db.query(User).filter(
        User.id == user_id
    ).first()

    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    if not current_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )

    if payload.get("token_version") != current_user.token_version:
        raise HTTPException(
            status_code=401,
            detail="Token version is invalid"
        )

    db.add(
        RevokedToken(
            jti=jti,
            expires_at=datetime.fromtimestamp(
                payload["exp"],
                tz=timezone.utc
            )
        )
    )

    token_data = {
        "sub": str(current_user.id),
        "token_version": current_user.token_version
    }

    new_access_token = create_access_token(data=token_data)
    new_refresh_token = create_refresh_token(data=token_data)

    db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }
