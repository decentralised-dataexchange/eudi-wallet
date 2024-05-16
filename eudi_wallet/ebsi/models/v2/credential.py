import datetime
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class CredentialModel(Base):
    __tablename__ = "credential"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )

    organisationId = Column(
        UUID(as_uuid=True),
        ForeignKey("organisation.id"),
        nullable=False,
    )

    credentialExchangeId = Column(
        UUID(as_uuid=True),
        ForeignKey("issue_credential_record.id"),
        nullable=False,
    )

    credentialToken = Column(String, nullable=True)
    credential = Column(JSON, nullable=True, default={})

    credentialStatus = Column(String, nullable=True)
    acceptanceToken = Column(String, nullable=True)

    deferredEndpoint = Column(String, nullable=True)

    createdAt = Column(DateTime, default=datetime.datetime.utcnow)
    updatedAt = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}

        # Convert datetime objects to seconds since epoch (Unix timestamp)
        for attr in ["createdAt", "updatedAt"]:
            if attr in result and isinstance(result[attr], datetime.datetime):
                result[attr] = int(result[attr].timestamp())

        # Convert UUID to string
        for attr in ["id", "credentialExchangeId", "organisationId"]:
            if attr in result and isinstance(result[attr], uuid.UUID):
                result[attr] = str(result[attr])

        return result
