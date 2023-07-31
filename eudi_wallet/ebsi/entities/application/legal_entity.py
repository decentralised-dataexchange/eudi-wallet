import datetime
import uuid

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.entities.base import Base


class LegalEntityEntity(Base):
    __tablename__ = "legal_entity"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )
    credential_schemas = relationship(
        "CredentialSchemaEntity", back_populates="legal_entity", cascade="all,delete-orphan"
    )
    cryptographic_seed = Column(String(length=200), nullable=False)
    role = Column(String(length=200), nullable=False)
    is_onboarding_in_progress = Column(Boolean, default=False)
    is_onboarded = Column(Boolean, default=False)
    verifiable_authorisation_to_onboard = Column(Text, nullable=True)
    verifiable_accreditation_to_attest = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
