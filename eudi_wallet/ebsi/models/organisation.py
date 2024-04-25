import datetime
import uuid

from sqlalchemy import Boolean, Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class OrganisationModel(Base):
    __tablename__ = "organisation"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    data_agreements = relationship(
        "DataAgreementModel",
        back_populates="organisation",
        cascade="all,delete-orphan",
    )
    v2_data_agreements = relationship(
        "V2DataAgreementModel",
        back_populates="organisation",
        cascade="all,delete-orphan",
    )
    name = Column(String(length=100), nullable=False)
    description = Column(String(length=500), nullable=True)
    logo_url = Column(Text, nullable=True)
    cryptographic_seed = Column(String(length=500), nullable=False)
    role = Column(String(length=200), nullable=False)
    location = Column(String(length=100), nullable=True)
    cover_image_url = Column(Text, nullable=True)
    webhook_url = Column(Text, nullable=True)

    is_did_in_registry = Column(Boolean, default=False)

    # FIXME: Need to understand about this fields
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

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}

        # Convert datetime objects to seconds since epoch (Unix timestamp)
        for attr in ["created_at", "updated_at"]:
            if attr in result and isinstance(result[attr], datetime.datetime):
                result[attr] = int(result[attr].timestamp())

        # Convert UUID to string
        for attr in ["id"]:
            if attr in result and isinstance(result[attr], uuid.UUID):
                result[attr] = str(result[attr])

        return result
