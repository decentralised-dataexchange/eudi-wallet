from logging import Logger
from typing import List
from eudi_wallet.ebsi.models.v2.credential import CredentialModel
from eudi_wallet.ebsi.repositories.v2.credential import (
    SqlAlchemyCredentialRepository,
)


class ListCredentialUsecase:
    def __init__(
        self,
        repository: SqlAlchemyCredentialRepository,
        logger: Logger,
    ) -> None:
        self.repository = repository
        self.logger = logger

    def execute(
        self,
        organisation_id: str,
    ) -> List[CredentialModel]:
        with self.repository as repo:
            credentials = repo.get_all_by_organisation_id(
                organisation_id=organisation_id
            )
        return credentials
