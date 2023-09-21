import uuid
from logging import Logger
from typing import Callable, List, Optional, Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.credential_offer import CredentialOfferModel


class SqlAlchemyCredentialOfferRepository:
    def __init__(self, session: Optional[Callable], logger: Optional[Logger]):
        self.session_factory = session
        self.logger = logger
        self.session = None

    def __enter__(self):
        assert self.session_factory is not None
        self.session = self.session_factory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self.session is not None, "DB session not available"
        assert self.logger is not None, "Logger not available"
        if exc_tb is not None:
            self.session.rollback()
            self.logger.error(f"Exception occurred: {exc_type}, {exc_val}")
            return False

        self.session.close()
        self.session = None
        return True

    def get_by_id_and_credential_schema_id(
        self, id: str, data_agreement_id: str
    ) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(
                    CredentialOfferModel.id == id,
                    CredentialOfferModel.data_agreement_id == data_agreement_id,
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with id {id} and credential schema id {data_agreement_id}"
            )
            return None

    def get_all_by_client_id(self, client_id: str) -> List[CredentialOfferModel]:
        assert self.session is not None
        return (
            self.session.query(CredentialOfferModel)
            .filter(CredentialOfferModel.client_id == client_id)
            .all()
        )

    def get_by_id(self, id: str) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No CredentialOfferModel found with id {id}")
            return None

    def get_by_acceptance_token(
        self, acceptance_token: str
    ) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.acceptance_token == acceptance_token)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with acceptance_token {acceptance_token}"
            )
            return None

    def get_by_vp_token_request_state(
        self, state: str
    ) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.vp_token_request_state == state)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with vp token state {state}"
            )
            return None

    def get_by_id_token_request_state(
        self, state: str
    ) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.id_token_request_state == state)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with id token state {state}"
            )
            return None

    def get_by_authorisation_code(
        self, authorisation_code: str
    ) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.authorisation_code == authorisation_code)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with authorisation code {authorisation_code}"
            )
            return None

    def get_by_pre_authorised_code(
        self, pre_authorised_code: str
    ) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialOfferModel)
                .filter(
                    CredentialOfferModel.pre_authorised_code == pre_authorised_code
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with pre-authorised code {pre_authorised_code}"
            )
            return None

    def get_all_by_credential_schema_id(
        self, data_agreement_id: str
    ) -> List[CredentialOfferModel]:
        assert self.session is not None
        return (
            self.session.query(CredentialOfferModel)
            .filter(
                CredentialOfferModel.data_agreement_id == data_agreement_id,
            )
            .all()
        )

    def get_all(self) -> List[CredentialOfferModel]:
        assert self.session is not None
        return self.session.query(CredentialOfferModel).all()

    def delete(self, id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential_offer = (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.id == id)
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
        data_agreement_id: str,
        issuance_mode: str,
        data_attribute_values: Optional[str] = None,
        **kwargs,
    ) -> CredentialOfferModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        credential_offer = CredentialOfferModel(
            id=id,
            data_agreement_id=data_agreement_id,
            data_attribute_values=data_attribute_values,
            issuance_mode=issuance_mode,
            **kwargs,
        )
        self.session.add(credential_offer)
        self.session.commit()
        self.session.refresh(credential_offer)
        return credential_offer

    def update(self, id: str, **kwargs) -> Union[CredentialOfferModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential_offer: CredentialOfferModel = (
                self.session.query(CredentialOfferModel)
                .filter(CredentialOfferModel.id == id)
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
