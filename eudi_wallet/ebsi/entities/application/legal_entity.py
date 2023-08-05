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
        "CredentialSchemaEntity",
        back_populates="legal_entity",
        cascade="all,delete-orphan",
    )
    cryptographic_seed = Column(String(length=200), nullable=False)
    role = Column(String(length=200), nullable=False)

    is_did_in_registry = Column(Boolean, default=False)

    is_onboarding_as_ti_in_progress = Column(Boolean, default=False)
    is_onboarded_as_ti = Column(Boolean, default=False)

    verifiable_authorisation_to_onboard = Column(Text, nullable=True)
    verifiable_accreditation_to_attest = Column(Text, nullable=True)
    verifiable_authorisation_for_trust_chain = Column(Text, nullable=True)

    is_onboarding_as_tao_in_progress = Column(Boolean, default=False)
    is_onboarded_as_tao = Column(Boolean, default=False)

    is_onboarding_as_root_tao_in_progress = Column(Boolean, default=False)
    is_onboarded_as_root_tao = Column(Boolean, default=False)

    verifiable_accreditation_to_accredit = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
