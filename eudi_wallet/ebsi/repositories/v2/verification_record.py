import uuid
from logging import Logger
from typing import Callable, List, Optional, Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.v2.verification_record import (
    VerificationRecordModel,
)


class SqlAlchemyVerificationRecordRepository:
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
        id: str,
        organisation_id: str,
        status: str,
        vp_token_request_state: Optional[str] = None,
        vp_token_request: Optional[str] = None,
        vp_token_qr_code: Optional[str] = None,
        vp_token_response: Optional[str] = None,
        presentationSubmission: Optional[dict] = None,
        **kwargs,
    ) -> VerificationRecordModel:
        assert self.session is not None
        verification_record = VerificationRecordModel(
            id=id,
            organisationId=organisation_id,
            vp_token_request_state=vp_token_request_state,
            vp_token_request=vp_token_request,
            vp_token_qr_code=vp_token_qr_code,
            vp_token_response=vp_token_response,
            presentationSubmission=presentationSubmission,
            status=status,
            **kwargs,
        )
        self.session.add(verification_record)
        self.session.commit()
        self.session.refresh(verification_record)
        return verification_record

    def update(self, id: str, **kwargs) -> Union[VerificationRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            verification_record: VerificationRecordModel = (
                self.session.query(VerificationRecordModel)
                .filter(VerificationRecordModel.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(verification_record, attribute, value)

            self.session.commit()
            self.session.refresh(verification_record)
            return verification_record
        except exc.NoResultFound:
            self.logger.debug(f"No verification record found with ID: {id}")
            return None

    def get_by_id(self, id: str) -> Union[VerificationRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            verification_records = (
                self.session.query(VerificationRecordModel)
                .filter(VerificationRecordModel.id == id)
                .all()
            )
            if len(verification_records) > 0:
                return verification_records[0]
            else:
                return None
        except exc.NoResultFound:
            self.logger.debug(f"No verification record found with ID: {id}")
            return None

    def get_by_vp_token_request_state(
        self, vp_token_request_state: str
    ) -> Union[VerificationRecordModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(VerificationRecordModel)
                .filter(
                    VerificationRecordModel.vp_token_request_state
                    == vp_token_request_state
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No verification record found with vp token request state {vp_token_request_state}"
            )
            return None

    def get_all_by_organisation_id(
        self, organisation_id: str
    ) -> List[VerificationRecordModel]:
        assert self.session is not None
        return (
            self.session.query(VerificationRecordModel)
            .filter(
                VerificationRecordModel.organisationId == organisation_id,
            )
            .all()
        )

    def delete(self, id: str, organisation_id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            verification_record = (
                self.session.query(VerificationRecordModel)
                .filter(
                    VerificationRecordModel.id == id,
                    VerificationRecordModel.organisationId == organisation_id,
                )
                .one()
            )
            self.session.delete(verification_record)
            self.session.commit()
            self.logger.debug(f"Verification record with ID: {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No verification record found with id {id}")
            return False
