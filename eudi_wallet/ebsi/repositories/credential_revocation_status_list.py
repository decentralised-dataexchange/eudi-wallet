from logging import Logger
from typing import Callable, Optional, Union
import uuid

from sqlalchemy import exc
from sqlalchemy.orm import Session

from eudi_wallet.ebsi.models.credential_revocation_status_list import (
    CredentialRevocationStatusListModel,
)
from eudi_wallet.ebsi.services.domain.utils.credential import (
    CredentialStatus,
    generate_w3c_vc_statuslist_encoded_bitstring,
)


class SqlAlchemyCredentialRevocationStatusListRepository:
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

    def create(
        self,
        encoded_status_list: str,
        last_assigned_index: Optional[int] = None,
        **kwargs,
    ) -> CredentialRevocationStatusListModel:
        assert self.session is not None
        id = str(uuid.uuid4())
        credential_revocation_status_list_entity = CredentialRevocationStatusListModel(
            id=id,
            encoded_status_list=encoded_status_list,
            last_assigned_index=last_assigned_index,
            **kwargs,
        )
        self.session.add(credential_revocation_status_list_entity)
        self.session.commit()
        self.session.refresh(credential_revocation_status_list_entity)
        return credential_revocation_status_list_entity

    def reserve_revocation_index(
        self,
    ) -> CredentialRevocationStatusListModel:
        assert self.session is not None
        assert self.logger is not None
        revocation_list: CredentialRevocationStatusListModel = (
            self.session.query(CredentialRevocationStatusListModel)
            .order_by(CredentialRevocationStatusListModel.created_at.desc())
            .filter(CredentialRevocationStatusListModel.last_assigned_index < 131071)
            .with_for_update()
            .first()
        )
        if revocation_list:
            revocation_list.last_assigned_index += 1 # type: ignore
        else:
            self.logger.debug(
                "No credential revocation status list found with last assigned index < 131071; Creating new list"
            )
            id = str(uuid.uuid4())
            encoded_status_list = generate_w3c_vc_statuslist_encoded_bitstring(
                credential_statuses=[
                    CredentialStatus(status_list_index=0, is_revoked=False)
                ]
            )
            revocation_list = CredentialRevocationStatusListModel(
                id=id,
                encoded_status_list=encoded_status_list,
                last_assigned_index=0,
            )
            self.session.add(revocation_list)

        self.session.commit()
        self.session.refresh(revocation_list)

        return revocation_list

    def get_by_id(self, id: str) -> Union[CredentialRevocationStatusListModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            return (
                self.session.query(CredentialRevocationStatusListModel)
                .filter(CredentialRevocationStatusListModel.id == id)
                .one()
            )
        except exc.NoResultFound:
            self.logger.debug(
                f"No credential revocation status list found with id {id}"
            )
            return None

    def update(
        self, id: str, **kwargs
    ) -> Union[CredentialRevocationStatusListModel, None]:
        assert self.session is not None
        assert self.logger is not None
        try:
            credential_revocation_status_list_entity: CredentialRevocationStatusListModel = (
                self.session.query(CredentialRevocationStatusListModel)
                .filter(CredentialRevocationStatusListModel.id == id)
                .one()
            )

            for attribute, value in kwargs.items():
                if value is not None:
                    setattr(credential_revocation_status_list_entity, attribute, value)

            self.session.commit()
            self.session.refresh(credential_revocation_status_list_entity)
            return credential_revocation_status_list_entity
        except exc.NoResultFound:
            self.logger.debug(
                f"No credential revocation status list found with id {id}"
            )
            return None
