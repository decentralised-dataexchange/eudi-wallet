import datetime
import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String, Boolean
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class V2DataAgreementModel(Base):
    __tablename__ = "v2_data_agreement"

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
    organisation = relationship(
        "OrganisationModel", back_populates="v2_data_agreements"
    )
    issue_credential_record = relationship(
        "IssueCredentialRecordModel",
        back_populates="dataAgreement",
        cascade="all,delete-orphan",
    )

    # Name of the data agreement
    purpose = Column(String(500), nullable=False)

    # Description of the data agreement
    purposeDescription = Column(String(500), nullable=False)

    # List of data attributes to be present in a credential
    # For e.g. [{"attribute_name": "Name", "attribute_description": "Name of the individual"}]
    dataAttributes = Column(JSON, nullable=False)

    # Exchange mode of a data agreement
    # For e.g. data-source, data-using-service
    methodOfUse = Column(String(50), nullable=False)

    limitedDisclosure = Column(Boolean, default=True)

    # Types satisfied by a credential
    # For e.g. ["VerifiableCredential", "VerifiableAttestation", "DiplomaCertificate"]
    credentialTypes = Column(JSON, nullable=False)

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
