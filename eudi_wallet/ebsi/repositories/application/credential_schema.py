import uuid
from logging import Logger
from typing import List, Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.entities.application.credential_schema import \
    CredentialSchemaEntity


class SqlAlchemyCredentialSchemaRepository:
    def __init__(self, session: Session, logger: Logger):
        self.session_factory = session
        self.logger = logger

    def __enter__(self):
        self.session = self.session_factory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_tb is not None:
            self.session.rollback()
            self.logger.error(f"Exception occurred: {exc_type}, {exc_val}")
            return False

        self.session.close()
        self.session = None
        return True

    def get_first(self) -> Union[CredentialSchemaEntity, None]:
        return self.session.query(CredentialSchemaEntity).first()

    def get_by_id(self, id: str) -> Union[CredentialSchemaEntity, None]:
        try:
            return (
                self.session.query(CredentialSchemaEntity)
                .filter(CredentialSchemaEntity.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No CredentialSchemaEntity found with id {id}")
            return None

    def get_all(self) -> List[CredentialSchemaEntity]:
        return self.session.query(CredentialSchemaEntity).all()

    def update(self, id: str, **kwargs) -> Union[CredentialSchemaEntity, None]:
        try:
            legal_entity: CredentialSchemaEntity = (
                self.session.query(CredentialSchemaEntity)
                .filter(CredentialSchemaEntity.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(legal_entity, attribute, value)

            self.session.commit()
            self.session.refresh(legal_entity)
            return legal_entity
        except exc.NoResultFound:
            self.logger.debug(f"No credential schema found with id {id}")
            return None

    def delete(self, id: str) -> bool:
        try:
            legal_entity = (
                self.session.query(CredentialSchemaEntity)
                .filter(CredentialSchemaEntity.id == id)
                .one()
            )
            self.session.delete(legal_entity)
            self.session.commit()
            self.logger.debug(f"Credential schema with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No credential schema found with id {id}")
            return False

    def create(
        self,
        legal_entity_id: str,
        credential_type: str,
        data_attributes: str,
        **kwargs,
    ) -> CredentialSchemaEntity:
        id = str(uuid.uuid4())
        legal_entity = CredentialSchemaEntity(
            id=id,
            legal_entity_id=legal_entity_id,
            credential_type=credential_type,
            data_attributes=data_attributes,
            **kwargs,
        )
        self.session.add(legal_entity)
        self.session.commit()
        self.session.refresh(legal_entity)
        return legal_entity
