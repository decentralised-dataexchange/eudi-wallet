import datetime
import json
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
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

    data_attribute_values = Column(Text, nullable=False)
    issuance_mode = Column(String, nullable=False)

    issuer_state = Column(String, nullable=True)
    authorisation_request_state = Column(String, nullable=True)
    id_token_request_state = Column(String, nullable=True)
    authorisation_code_state = Column(String, nullable=True)
    id_token_request = Column(String, nullable=True)

    client_id = Column(String, nullable=True)
    code_challenge = Column(String, nullable=True)
    code_challenge_method = Column(String, nullable=True)
    redirect_uri = Column(String, nullable=True)

    authorisation_code = Column(String, nullable=True)
    pre_authorized_code = Column(String, nullable=True)
    user_pin = Column(String, nullable=True)

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

        # Convert data attributes values to dict from string
        if "data_attribute_values" in result and isinstance(
            result["data_attribute_values"], str
        ):
            result["data_attribute_values"] = json.loads(
                result["data_attribute_values"]
            )

        return result
