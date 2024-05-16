import uuid
from logging import Logger
from typing import Callable, List, Optional, Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.v2.credential import (
    CredentialModel,
)


class SqlAlchemyCredentialRepository:
    def __init__(self, session: Optional[Callable], logger: Optional[Logger]):
        self.session_factory = session
        self.logger = logger
        self.session = None

    def __enter__(self):
        assert self.session_factory is not None
        self.session = self.session_factory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self.logger is not None, "Logger not available"
        self.logger.error(f"Exception occurred: {exc_type}, {exc_val}")
        assert self.session is not None, "DB session not available"
        if exc_tb is not None:
            self.session.rollback()
            return False

        self.session.close()
        self.session = None
        return True

    def create(
        self,
        credential_exchange_id: str,
        organisation_id: str,
        status: str,
        acceptance_token: Optional[str] = None,
        credential_token: Optional[bool] = False,
        credential_token_decoded: Optional[dict] = None,
        deferred_endpoint: Optional[str] = None,
        **kwargs,
    ) -> CredentialModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        credential = CredentialModel(
            id=id,
            organisationId=organisation_id,
            credentialExchangeId=credential_exchange_id,
            credentialToken=credential_token,
            credential=credential_token_decoded,
            credentialStatus=status,
            acceptanceToken=acceptance_token,
            deferredEndpoint=deferred_endpoint,
            **kwargs,
        )
        self.session.add(credential)
        self.session.commit()
        self.session.refresh(credential)
        return credential

    def update(self, id: str, **kwargs) -> Union[CredentialModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential: CredentialModel = (
                self.session.query(CredentialModel)
                .filter(CredentialModel.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(credential, attribute, value)

            self.session.commit()
            self.session.refresh(credential)
            return credential
        except exc.NoResultFound:
            self.logger.debug(f"No credential found with id {id}")
            return None

    def get_by_id(self, id: str) -> Union[CredentialModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialModel)
                .filter(CredentialModel.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No credential found with id {id}")
            return None

    def get_by_acceptance_token(
        self, acceptance_token: str
    ) -> Union[CredentialModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialModel)
                .filter(CredentialModel.acceptanceToken == acceptance_token)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No credential found with acceptance_token {acceptance_token}"
            )
            return None

    def get_all_by_organisation_id(self, organisation_id: str) -> List[CredentialModel]:
        assert self.session is not None
        return (
            self.session.query(CredentialModel)
            .filter(
                CredentialModel.organisationId == organisation_id,
            )
            .all()
        )

    def get_by_organisation_id_and_credential_id(
        self, organisation_id: str, credential_id: str
    ) -> Union[CredentialModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialModel)
                .filter(
                    CredentialModel.organisationId == organisation_id,
                    CredentialModel.id == credential_id,
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No Credential found with organisation id {organisation_id} and credential id {credential_id}"
            )
            return None

    def delete(self, id: str, organisation_id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential = (
                self.session.query(CredentialModel)
                .filter(
                    CredentialModel.id == id,
                    CredentialModel.organisationId == organisation_id,
                )
                .one()
            )
            self.session.delete(credential)
            self.session.commit()
            self.logger.debug(f"Credential with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No credential found with id {id}")
            return False
