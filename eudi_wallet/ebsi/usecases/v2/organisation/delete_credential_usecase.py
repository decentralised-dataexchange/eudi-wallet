from logging import Logger
from eudi_wallet.ebsi.models.v2.credential import CredentialModel
from eudi_wallet.ebsi.repositories.v2.credential import (
    SqlAlchemyCredentialRepository,
)


class DeleteCredentialUsecaseError(Exception):
    pass


class DeleteCredentialUsecase:
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
        credential_id: str,
    ) -> CredentialModel:
        with self.repository as repo:
            is_deleted = repo.delete(id=credential_id, organisation_id=organisation_id)
            if not is_deleted:
                raise DeleteCredentialUsecaseError("Credential is not found")
        return is_deleted
