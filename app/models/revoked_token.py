
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime, timezone

from app.database import Base


class RevokedToken(Base):

    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)

    jti = Column(String, unique=True, nullable=False, index=True)

    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )

    revoked_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
