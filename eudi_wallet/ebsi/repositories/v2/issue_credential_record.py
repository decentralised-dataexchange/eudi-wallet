import uuid
from logging import Logger
from typing import Callable, List, Optional, Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.v2.issue_credential_record import (
    IssueCredentialRecordModel,
)


class SqlAlchemyIssueCredentialRecordRepository:
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

    def create_without_data_agreement(
        self,
        organisation_id: str,
        issuance_mode: str,
        status: str,
        is_pre_authorised: Optional[bool] = False,
        credential_status: Optional[str] = None,
        acceptance_token: Optional[str] = None,
        authorisation_code: Optional[str] = None,
        pre_authorised_code: Optional[str] = None,
        user_pin: Optional[str] = None,
        **kwargs,
    ) -> IssueCredentialRecordModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        credential_offer = IssueCredentialRecordModel(
            id=id,
            organisationId=organisation_id,
            issuanceMode=issuance_mode,
            isPreAuthorised=is_pre_authorised,
            credentialStatus=credential_status,
            acceptanceToken=acceptance_token,
            authorisationCode=authorisation_code,
            preAuthorisedCode=pre_authorised_code,
            userPin=user_pin,
            status=status,
            **kwargs,
        )
        self.session.add(credential_offer)
        self.session.commit()
        self.session.refresh(credential_offer)
        return credential_offer

    def create(
        self,
        data_agreement_id: str,
        organisation_id: str,
        issuance_mode: str,
        status: str,
        data_attribute_values: Optional[str] = None,
        is_pre_authorised: Optional[bool] = False,
        credential_status: Optional[str] = None,
        acceptance_token: Optional[str] = None,
        authorisation_code: Optional[str] = None,
        pre_authorised_code: Optional[str] = None,
        user_pin: Optional[str] = None,
        **kwargs,
    ) -> IssueCredentialRecordModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        credential_offer = IssueCredentialRecordModel(
            id=id,
            dataAgreementId=data_agreement_id,
            organisationId=organisation_id,
            dataAttributeValues=data_attribute_values,
            issuanceMode=issuance_mode,
            isPreAuthorised=is_pre_authorised,
            credentialStatus=credential_status,
            acceptanceToken=acceptance_token,
            authorisationCode=authorisation_code,
            preAuthorisedCode=pre_authorised_code,
            userPin=user_pin,
            status=status,
            **kwargs,
        )
        self.session.add(credential_offer)
        self.session.commit()
        self.session.refresh(credential_offer)
        return credential_offer

    def update(self, id: str, **kwargs) -> Union[IssueCredentialRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential_offer: IssueCredentialRecordModel = (
                self.session.query(IssueCredentialRecordModel)
                .filter(IssueCredentialRecordModel.id == id)
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

    def get_by_id(self, id: str) -> Union[IssueCredentialRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(IssueCredentialRecordModel)
                .filter(IssueCredentialRecordModel.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No CredentialOfferModel found with id {id}")
            return None

    def get_all_by_client_id(self, client_id: str) -> List[IssueCredentialRecordModel]:
        assert self.session is not None
        return (
            self.session.query(IssueCredentialRecordModel)
            .filter(IssueCredentialRecordModel.clientId == client_id)
            .all()
        )

    def get_by_id_token_request_state(
        self, state: str
    ) -> Union[IssueCredentialRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(IssueCredentialRecordModel)
                .filter(IssueCredentialRecordModel.idTokenRequestState == state)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with id token state {state}"
            )
            return None

    def get_by_authorisation_code(
        self, authorisation_code: str
    ) -> Union[IssueCredentialRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(IssueCredentialRecordModel)
                .filter(
                    IssueCredentialRecordModel.authorisationCode == authorisation_code
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with authorisation code {authorisation_code}"
            )
            return None

    def get_by_acceptance_token(
        self, acceptance_token: str
    ) -> Union[IssueCredentialRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(IssueCredentialRecordModel)
                .filter(IssueCredentialRecordModel.acceptanceToken == acceptance_token)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with acceptance_token {acceptance_token}"
            )
            return None

    def get_by_id_and_data_agreement_id(
        self, id: str, data_agreement_id: str
    ) -> Union[IssueCredentialRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(IssueCredentialRecordModel)
                .filter(
                    IssueCredentialRecordModel.id == id,
                    IssueCredentialRecordModel.dataAgreementId == data_agreement_id,
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No CredentialOfferModel found with id {id} and credential schema id {data_agreement_id}"
            )
            return None

    def get_all_by_organisation_id(
        self, organisation_id: str
    ) -> List[IssueCredentialRecordModel]:
        assert self.session is not None
        return (
            self.session.query(IssueCredentialRecordModel)
            .filter(
                IssueCredentialRecordModel.organisationId == organisation_id,
            )
            .all()
        )
    
    def get_all_by_organisation_id_and_with_credential(
        self, organisation_id: str
    ) -> List[IssueCredentialRecordModel]:
        assert self.session is not None
        return (
            self.session.query(IssueCredentialRecordModel)
            .filter(
                IssueCredentialRecordModel.organisationId == organisation_id,
                IssueCredentialRecordModel.dataAgreementId == None
            )
            .all()
        )

    def get_all_by_data_agreement_id(
        self, data_agreement_id: str
    ) -> List[IssueCredentialRecordModel]:
        assert self.session is not None
        return (
            self.session.query(IssueCredentialRecordModel)
            .filter(
                IssueCredentialRecordModel.dataAgreementId == data_agreement_id,
            )
            .all()
        )

    def delete(self, id: str, organisation_id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential_offer = (
                self.session.query(IssueCredentialRecordModel)
                .filter(
                    IssueCredentialRecordModel.id == id,
                    IssueCredentialRecordModel.organisationId == organisation_id,
                )
                .one()
            )
            self.session.delete(credential_offer)
            self.session.commit()
            self.logger.debug(f"Credential offer with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No credential offer found with id {id}")
            return False
