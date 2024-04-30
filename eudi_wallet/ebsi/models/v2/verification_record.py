import datetime
import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String, Boolean
from sqlalchemy.dialects.postgresql import JSON, UUID

from eudi_wallet.ebsi.models.base import Base


class VerificationRecordModel(Base):
    __tablename__ = "verification_record"

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

    vp_token_request_state = Column(String, nullable=True)
    vp_token_request = Column(String, nullable=True)
    vp_token_qr_code = Column(String, nullable=True)
    vp_token_response = Column(String, nullable=True)
    presentationSubmission = Column(JSON, nullable=True, default={})
    status = Column(String, nullable=False)
    verified = Column(Boolean, default=False, nullable=True)
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
        for attr in ["id", "organisationId"]:
            if attr in result and isinstance(result[attr], uuid.UUID):
                result[attr] = str(result[attr])

        return result
