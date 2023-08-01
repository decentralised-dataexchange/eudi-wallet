import uuid
from logging import Logger
from typing import Union

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.entities.application.legal_entity import \
    LegalEntityEntity


class SqlAlchemyLegalRepository:
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

    def get_first(self) -> Union[LegalEntityEntity, None]:
        return self.session.query(LegalEntityEntity).first()

    def update(self, id: str, **kwargs) -> Union[LegalEntityEntity, None]:
        try:
            legal_entity: LegalEntityEntity = (
                self.session.query(LegalEntityEntity)
                .filter(LegalEntityEntity.id == id)
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
        try:
            legal_entity = (
                self.session.query(LegalEntityEntity)
                .filter(LegalEntityEntity.id == id)
                .one()
            )
            self.session.delete(legal_entity)
            self.session.commit()
            self.logger.debug(f"Legal entity with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            print(f"No legal entity found with id {id}")
            return False

    def create(self, **kwargs) -> LegalEntityEntity:
        id = str(uuid.uuid4())
        legal_entity = LegalEntityEntity(id=id, **kwargs)
        self.session.add(legal_entity)
        self.session.commit()
        self.session.refresh(legal_entity)
        return legal_entity
