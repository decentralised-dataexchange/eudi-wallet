import datetime
import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class DataAgreementModel(Base):
    __tablename__ = "data_agreement"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    organisation_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organisation.id"),
        nullable=False,
    )
    organisation = relationship("OrganisationModel", back_populates="data_agreements")
    credential_offers = relationship(
        "CredentialOfferModel",
        back_populates="data_agreement",
        cascade="all,delete-orphan",
    )

    # Name of the data agreement
    name = Column(String(500), nullable=False)

    # Types satisfied by a credential
    # For e.g. ["VerifiableCredential", "VerifiableAttestation", "DiplomaCertificate"]
    credential_types = Column(JSON, nullable=False)

    # List of data attributes to be present in a credential
    # For e.g. [{"attribute_name": "Name", "attribute_description": "Name of the individual"}]
    data_attributes = Column(JSON, nullable=False)

    # Exchange mode of a data agreement
    # For e.g. data-source, data-using-service
    exchange_mode = Column(String(50), nullable=False)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}
        print(result)

        # Convert datetime objects to seconds since epoch (Unix timestamp)
        for attr in ["created_at", "updated_at"]:
            if attr in result and isinstance(result[attr], datetime.datetime):
                result[attr] = int(result[attr].timestamp())

        # Convert UUID to string
        for attr in ["id", "organisation_id"]:
            if attr in result and isinstance(result[attr], uuid.UUID):
                result[attr] = str(result[attr])

        return result
