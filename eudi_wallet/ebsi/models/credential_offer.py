import datetime
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.models.base import Base


class CredentialOfferModel(Base):
    __tablename__ = "credential_offer"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    data_agreement_id = Column(
        UUID(as_uuid=True),
        ForeignKey("data_agreement.id"),
        nullable=False,
    )
    data_agreement = relationship(
        "DataAgreementModel", back_populates="credential_offers"
    )
    is_accessed = Column(Boolean, default=False)

    data_attribute_values = Column(JSON, nullable=False)

    issuance_mode = Column(String, nullable=False)
    is_pre_authorised = Column(Boolean, default=False)

    offer_status = Column(String, nullable=True)
    credential_status = Column(String, nullable=True)

    issuer_state = Column(String, nullable=True)
    authorisation_request_state = Column(String, nullable=True)
    id_token_request_state = Column(String, nullable=True)
    id_token_request = Column(String, nullable=True)
    authorisation_code_state = Column(String, nullable=True)

    # FIXME: Temporary hack to handle verifiable presentations
    vp_token_request_state = Column(String, nullable=True)
    vp_token_request = Column(String, nullable=True)
    vp_token_qr_code = Column(String, nullable=True)
    vp_token_response = Column(String, nullable=True)
    issuer_qr_code = Column(String, nullable=True)

    client_id = Column(String, nullable=True)
    code_challenge = Column(String, nullable=True)
    code_challenge_method = Column(String, nullable=True)
    redirect_uri = Column(String, nullable=True)

    acceptance_token = Column(String, nullable=True)

    authorisation_code = Column(String, nullable=True)
    pre_authorised_code = Column(String, nullable=True)
    user_pin = Column(String(length=4), nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    did = Column(String, nullable=True)

    # In EBSI, the trusted issuer and trusted accreditation organisation
    # issuer types are registered to trusted issuers registry.
    # Each issuer type has a corresponding reserved attribute id.
    # This reserved attribute holds the verifiable accreditation
    # that proves that these DIDs are of this issuer type and who
    # accredited them. Using this attribute ids, it is possible to
    # mark the DID as revoked for that particular issuer type.
    trusted_issuer_attribute_id = Column(String, nullable=True)
    trusted_accreditation_organisation_attribute_id = Column(String, nullable=True)

    # Revocation follows W3C StatusList2021 specification
    # Each status list can contain at-most 131,072 entries
    supports_revocation = Column(Boolean, default=False)
    is_revoked = Column(Boolean, default=False)
    credential_revocation_status_list_index = Column(
        Integer, nullable=False, default=-1
    )
    credential_revocation_status_list_id = Column(
        UUID(as_uuid=True),
        ForeignKey("credential_revocation_status_list.id"),
        nullable=True,
    )
    credential_revocation_status_list = relationship(
        "CredentialRevocationStatusListModel",
        back_populates="credential_offers",
    )

    trust_framework = Column(String, nullable=True)

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}

        # Convert datetime objects to seconds since epoch (Unix timestamp)
        for attr in ["created_at", "updated_at"]:
            if attr in result and isinstance(result[attr], datetime.datetime):
                result[attr] = int(result[attr].timestamp())

        # Convert UUID to string
        for attr in ["id", "data_agreement_id", "credential_revocation_status_list_id"]:
            if attr in result and isinstance(result[attr], uuid.UUID):
                result[attr] = str(result[attr])

        return result
