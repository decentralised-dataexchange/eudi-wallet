import datetime
import uuid

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class CredentialRevocationStatusListEntity(Base):
    __tablename__ = "credential_revocation_status_list"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )
    encoded_status_list = Column(Text, nullable=False)
    last_assigned_index = Column(Integer, default=-1, nullable=False)

    # Cascading on delete is not required as credential offer can
    # exist without a credential revocation status list
    credential_offer_entities = relationship(
        "CredentialOfferEntity", back_populates="credential_revocation_status_list"
    )

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}

        # Convert datetime objects to seconds since epoch (Unix timestamp)
        for attr in ["created_at", "updated_at"]:
            if attr in result and isinstance(result[attr], datetime.datetime):
                result[attr] = int(result[attr].timestamp())

        return result
