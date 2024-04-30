import datetime
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class IssueCredentialRecordModel(Base):
    __tablename__ = "issue_credential_record"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    dataAgreementId = Column(
        UUID(as_uuid=True),
        ForeignKey("v2_data_agreement.id"),
        nullable=True,
    )
    dataAgreement = relationship(
        "V2DataAgreementModel", back_populates="issue_credential_record"
    )

    organisationId = Column(
        UUID(as_uuid=True),
        ForeignKey("organisation.id"),
        nullable=False,
    )

    dataAttributeValues = Column(JSON, nullable=True, default="{}")
    credential = Column(JSON, nullable=True, default="{}")
    disclosureMapping = Column(JSON, nullable=True, default="{}")

    issuanceMode = Column(String, nullable=False)
    isPreAuthorised = Column(Boolean, default=False)

    credentialStatus = Column(String, nullable=True)

    acceptanceToken = Column(String, nullable=True)

    issuerState = Column(String, nullable=True)
    authorisationRequestState = Column(String, nullable=True)
    idTokenRequestState = Column(String, nullable=True)
    idTokenRequest = Column(String, nullable=True)
    authorisationCodeState = Column(String, nullable=True)

    authorisationCode = Column(String, nullable=True)
    preAuthorisedCode = Column(String, nullable=True)
    userPin = Column(String(length=4), nullable=True)

    clientId = Column(String, nullable=True)
    codeChallenge = Column(String, nullable=True)
    codeChallengeMethod = Column(String, nullable=True)
    redirectUri = Column(String, nullable=True)

    did = Column(String, nullable=True)

    status = Column(String, nullable=False)
    isAccessed = Column(Boolean, default=False)

    limitedDisclosure = Column(Boolean, default=True, nullable=False, server_default="True")

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
        for attr in ["id", "dataAgreementId", "organisationId"]:
            if attr in result and isinstance(result[attr], uuid.UUID):
                result[attr] = str(result[attr])

        return result
