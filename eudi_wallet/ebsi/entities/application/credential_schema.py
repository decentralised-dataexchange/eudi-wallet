import datetime
import json
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from eudi_wallet.ebsi.entities.base import Base


class CredentialSchemaEntity(Base):
    __tablename__ = "credential_schema"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )
    legal_entity_id = Column(
        String(36),
        ForeignKey("legal_entity.id"),
        nullable=False,
    )
    credential_offer_entities = relationship(
        "CredentialOfferEntity", back_populates="credential_schema", cascade="all,delete-orphan"
    )
    legal_entity = relationship("LegalEntityEntity", back_populates="credential_schemas")

    credential_type = Column(String, nullable=False)

    # List of data attributes
    data_attributes = Column(Text, nullable=False)

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

        # Convert data attributes to list from string
        if "data_attributes" in result and isinstance(result["data_attributes"], str):
            result["data_attributes"] = json.loads(result["data_attributes"])

        return result
