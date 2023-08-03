import datetime
import json
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.entities.base import Base


class CredentialOfferEntity(Base):
    __tablename__ = "credential_offer"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )
    credential_schema_id = Column(
        String(36),
        ForeignKey("credential_schema.id"),
        nullable=False,
    )
    credential_schema = relationship(
        "CredentialSchemaEntity", back_populates="credential_offer_entities"
    )
    is_accessed = Column(Boolean, default=False)

    data_attribute_values = Column(Text, nullable=True)

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

    # Revocation follows W3C StatusList2021 specification
    # Each status list can contain at-most 131,072 entries
    supports_revocation = Column(Boolean, default=False)
    is_revoked = Column(Boolean, default=False)
    credential_revocation_status_list_index = Column(
        Integer, nullable=False, default=-1
    )
    credential_revocation_status_list_id = Column(
        String(36),
        ForeignKey("credential_revocation_status_list.id"),
        nullable=True,
    )
    credential_revocation_status_list = relationship(
        "CredentialRevocationStatusListEntity",
        back_populates="credential_offer_entities",
    )

    def to_dict(self):
        result = {c.name: getattr(self, c.name) for c in self.__table__.columns}

        # Convert datetime objects to seconds since epoch (Unix timestamp)
        for attr in ["created_at", "updated_at"]:
            if attr in result and isinstance(result[attr], datetime.datetime):
                result[attr] = int(result[attr].timestamp())

        # Convert data attributes values to dict from string
        if "data_attribute_values" in result and isinstance(
            result["data_attribute_values"], str
        ):
            result["data_attribute_values"] = json.loads(
                result["data_attribute_values"]
            )

        return result
