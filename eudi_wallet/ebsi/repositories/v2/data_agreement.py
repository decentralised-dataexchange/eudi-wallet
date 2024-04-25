import uuid
from logging import Logger
from typing import List, Union, Optional, Callable

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.v2.data_agreement import V2DataAgreementModel


class SqlAlchemyV2DataAgreementRepository:
    def __init__(self, session: Optional[Callable], logger: Optional[Logger]):
        self.session_factory = session
        self.logger = logger
        self.session: Optional[Session] = None

    def __enter__(self):
        assert self.session_factory is not None
        self.session = self.session_factory()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self.session is not None
        assert self.logger is not None
        if exc_tb is not None:
            self.session.rollback()
            self.logger.error(f"Exception occurred: {exc_type}, {exc_val}")
            return False

        self.session.close()
        self.session = None
        return True

    def create(
        self,
        organisation_id: str,
        purpose: str,
        credential_types: List[str],
        data_attributes: List[dict],
        exchange_mode: str,
        purpose_description: str,
        limited_disclosure: bool,
        **kwargs,
    ) -> V2DataAgreementModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        legal_entity = V2DataAgreementModel(
            id=id,
            organisationId=organisation_id,
            purpose=purpose,
            purposeDescription=purpose_description,
            dataAttributes=data_attributes,
            methodOfUse=exchange_mode,
            limitedDisclosure=limited_disclosure,
            credentialTypes=credential_types,
            **kwargs,
        )
        self.session.add(legal_entity)
        self.session.commit()
        self.session.refresh(legal_entity)
        return legal_entity

    def get_all_by_organisation_id(
        self, organisation_id: str
    ) -> List[V2DataAgreementModel]:
        assert self.session is not None
        return (
            self.session.query(V2DataAgreementModel)
            .filter(V2DataAgreementModel.organisationId == organisation_id)
            .all()
        )

    def get_by_id_and_organisation_id(
        self, organisation_id: str, id: str
    ) -> Union[V2DataAgreementModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(V2DataAgreementModel)
                .filter(
                    V2DataAgreementModel.id == id,
                    V2DataAgreementModel.organisationId == organisation_id,
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No DataAgreementModel found with id {id}")
            return None

    def get_by_purpose_and_organisation_id(
        self, organisation_id: str, purpose: str
    ) -> Union[V2DataAgreementModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(V2DataAgreementModel)
                .filter(
                    V2DataAgreementModel.purpose == purpose,
                    V2DataAgreementModel.organisationId == organisation_id,
                )
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No DataAgreementModel found with id {id}")
            return None

    def update(
        self, id: str, organisation_id: str, **kwargs
    ) -> Union[V2DataAgreementModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity: V2DataAgreementModel = (
                self.session.query(V2DataAgreementModel)
                .filter(
                    V2DataAgreementModel.id == id,
                    V2DataAgreementModel.organisationId == organisation_id,
                )
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(legal_entity, attribute, value)

            self.session.commit()
            self.session.refresh(legal_entity)
            return legal_entity
        except exc.NoResultFound:
            self.logger.debug(f"No data agreement found with id {id}")
            return None

    def delete_by_organisation_id(self, id: str, organisation_id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity = (
                self.session.query(V2DataAgreementModel)
                .filter(
                    V2DataAgreementModel.id == id,
                    V2DataAgreementModel.organisationId == organisation_id,
                )
                .one()
            )
            self.session.delete(legal_entity)
            self.session.commit()
            self.logger.debug(f"Data agreement with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No data agreement found with id {id}")
            return False
