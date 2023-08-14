import uuid
from logging import Logger
from typing import List, Union, Optional, Callable

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.data_agreement import DataAgreementModel


class SqlAlchemyDataAgreementRepository:
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

    def get_first(self) -> Union[DataAgreementModel, None]:
        assert self.session is not None
        return self.session.query(DataAgreementModel).first()

    def get_by_id(self, id: str) -> Union[DataAgreementModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(DataAgreementModel)
                .filter(DataAgreementModel.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(f"No DataAgreementModel found with id {id}")
            return None

    def get_all_by_organisation_id(
        self, organisation_id: str
    ) -> List[DataAgreementModel]:
        assert self.session is not None
        return (
            self.session.query(DataAgreementModel)
            .filter(DataAgreementModel.organisation_id == organisation_id)
            .all()
        )

    def get_all(self) -> List[DataAgreementModel]:
        assert self.session is not None
        return self.session.query(DataAgreementModel).all()

    def update(self, id: str, **kwargs) -> Union[DataAgreementModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity: DataAgreementModel = (
                self.session.query(DataAgreementModel)
                .filter(DataAgreementModel.id == id)
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

    def delete(self, id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity = (
                self.session.query(DataAgreementModel)
                .filter(DataAgreementModel.id == id)
                .one()
            )
            self.session.delete(legal_entity)
            self.session.commit()
            self.logger.debug(f"Data agreement with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            self.logger.debug(f"No data agreement found with id {id}")
            return False

    def delete_by_organisation_id(self, id: str, organisation_id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity = (
                self.session.query(DataAgreementModel)
                .filter(
                    DataAgreementModel.id == id,
                    DataAgreementModel.organisation_id == organisation_id,
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

    def create(
        self,
        organisation_id: str,
        name: str,
        credential_types: List[str],
        data_attributes: List[dict],
        exchange_mode: str,
        **kwargs,
    ) -> DataAgreementModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        legal_entity = DataAgreementModel(
            id=id,
            organisation_id=organisation_id,
            name=name,
            credential_types=credential_types,
            data_attributes=data_attributes,
            exchange_mode=exchange_mode,
            **kwargs,
        )
        self.session.add(legal_entity)
        self.session.commit()
        self.session.refresh(legal_entity)
        return legal_entity
