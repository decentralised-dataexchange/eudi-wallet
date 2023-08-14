from logging import Logger
from typing import Callable, Optional, Union
import uuid

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.organisation import OrganisationModel


class SqlAlchemyOrganisationRepository:
    def __init__(self, session: Optional[Callable], logger: Optional[Logger]):
        self.session_factory = session
        self.logger = logger
        self.session = None

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

    def get_first(self) -> Union[OrganisationModel, None]:
        assert self.session is not None
        try:
            legal_entity = self.session.query(OrganisationModel).first()
            return legal_entity
        except Exception as e:
            print(e)
            return None

    def update(self, id: str, **kwargs) -> Union[OrganisationModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity: OrganisationModel = (
                self.session.query(OrganisationModel)
                .filter(OrganisationModel.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(legal_entity, attribute, value)

            self.session.commit()
            self.session.refresh(legal_entity)
            return legal_entity
        except exc.NoResultFound:
            self.logger.debug(f"No legal entity found with id {id}")
            return None

    def delete(self, id: str) -> bool:
        assert self.session is not None
        assert self.logger is not None
        try:
            legal_entity = (
                self.session.query(OrganisationModel)
                .filter(OrganisationModel.id == id)
                .one()
            )
            self.session.delete(legal_entity)
            self.session.commit()
            self.logger.debug(f"Legal entity with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            print(f"No legal entity found with id {id}")
            return False

    def create(self, **kwargs) -> OrganisationModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        legal_entity = OrganisationModel(id=id, **kwargs)
        self.session.add(legal_entity)
        self.session.commit()
        self.session.refresh(legal_entity)
        return legal_entity
