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

    def get_first(self) -> Union[LegalEntityEntity, None]:
        session: Session = self.session_factory()
        try:
            return session.query(LegalEntityEntity).first()
        finally:
            session.close()

    def update(self, id: str, **kwargs) -> Union[LegalEntityEntity, None]:
        session: Session = self.session_factory()
        try:
            legal_entity: LegalEntityEntity = (
                session.query(LegalEntityEntity)
                .filter(LegalEntityEntity.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(legal_entity, attribute, value)

            session.commit()
            session.refresh(legal_entity)
            return legal_entity
        except exc.NoResultFound:
            self.logger.debug(f"No legal entity found with id {id}")
            return None
        finally:
            session.close()

    def delete(self, id: str) -> bool:
        session: Session = self.session_factory()
        try:
            legal_entity = (
                session.query(LegalEntityEntity)
                .filter(LegalEntityEntity.id == id)
                .one()
            )
            session.delete(legal_entity)
            session.commit()
            self.logger.debug(f"Legal entity with id {id} has been deleted.")
            return True
        except exc.NoResultFound:
            print(f"No legal entity found with id {id}")
            return False
        finally:
            session.close()

    def create(self, **kwargs) -> LegalEntityEntity:
        session: Session = self.session_factory()
        try:
            id = str(uuid.uuid4())
            legal_entity = LegalEntityEntity(id=id, **kwargs)
            session.add(legal_entity)
            session.commit()
            session.refresh(legal_entity)
            return legal_entity
        finally:
            session.close()
