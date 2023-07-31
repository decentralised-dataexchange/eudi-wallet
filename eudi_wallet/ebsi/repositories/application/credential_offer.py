import uuid
from logging import Logger
from typing import List, Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.entities.application.credential_offer import \
    CredentialOfferEntity


class SqlAlchemyCredentialOfferRepository:
    def __init__(self, session: Session, logger: Logger):
        self.session_factory = session
        self.logger = logger
        self.session = None

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

    def get_by_id_and_credential_schema_id(
        self, id: str, credential_schema_id: str
    ) -> Union[CredentialOfferEntity, None]:
        try:
            return (
                self.session.query(CredentialOfferEntity)
                .filter(
                    CredentialOfferEntity.id == id,
                    CredentialOfferEntity.credential_schema_id == credential_schema_id,
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferEntity found with id {id} and credential schema id {credential_schema_id}"
            )
            return None

    def get_by_id(self, id: str) -> Union[CredentialOfferEntity, None]:
        try:
            return (
                self.session.query(CredentialOfferEntity)
                .filter(CredentialOfferEntity.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No CredentialOfferEntity found with id {id}")
            return None

    def get_by_id_token_request_state(
        self, state: str
    ) -> Union[CredentialOfferEntity, None]:
        try:
            return (
                self.session.query(CredentialOfferEntity)
                .filter(CredentialOfferEntity.id_token_request_state == state)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferEntity found with id token state {state}"
            )
            return None

    def get_by_authorisation_code(
        self, authorisation_code: str
    ) -> Union[CredentialOfferEntity, None]:
        try:
            return (
                self.session.query(CredentialOfferEntity)
                .filter(CredentialOfferEntity.authorisation_code == authorisation_code)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferEntity found with authorisation code {authorisation_code}"
            )
            return None

    def get_all_by_credential_schema_id(
        self, credential_schema_id: str
    ) -> List[CredentialOfferEntity]:
        return (
            self.session.query(CredentialOfferEntity)
            .filter(
                CredentialOfferEntity.credential_schema_id == credential_schema_id,
            )
            .all()
        )

    def get_all(self) -> List[CredentialOfferEntity]:
        return self.session.query(CredentialOfferEntity).all()

    def delete(self, id: str) -> bool:
        try:
            credential_offer = (
                self.session.query(CredentialOfferEntity)
                .filter(CredentialOfferEntity.id == id)
                .one()
            )
            self.session.delete(credential_offer)
            self.session.commit()
            self.logger.debug(f"Credential offer with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No credential offer found with id {id}")
            return False

    def create(
        self,
        credential_schema_id: str,
        data_attribute_values: str,
        issuance_mode: str,
        **kwargs,
    ) -> CredentialOfferEntity:
        id = str(uuid.uuid4())
        credential_offer = CredentialOfferEntity(
            id=id,
            credential_schema_id=credential_schema_id,
            data_attribute_values=data_attribute_values,
            issuance_mode=issuance_mode,
            **kwargs,
        )
        self.session.add(credential_offer)
        self.session.commit()
        self.session.refresh(credential_offer)
        return credential_offer

    def update(self, id: str, **kwargs) -> Union[CredentialOfferEntity, None]:
        try:
            credential_offer: CredentialOfferEntity = (
                self.session.query(CredentialOfferEntity)
                .filter(CredentialOfferEntity.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(credential_offer, attribute, value)

            self.session.commit()
            self.session.refresh(credential_offer)
            return credential_offer
        except exc.NoResultFound:
            self.logger.debug(f"No credential offer found with id {id}")
            return None
