from logging import Logger
from eudi_wallet.ebsi.models.v2.credential import CredentialModel
from eudi_wallet.ebsi.repositories.v2.credential import (
    SqlAlchemyCredentialRepository,
)


class ReadCredentialUsecaseError(Exception):
    pass


class ReadCredentialUsecase:
    def __init__(
        self,
        repository: SqlAlchemyCredentialRepository,
        logger: Logger,
    ) -> None:
        self.repository = repository
        self.logger = logger

    def execute(
        self,
        credential_id: str,
    ) -> CredentialModel:
        with self.repository as repo:
            credential = repo.get_by_id(id=credential_id)
            if credential is None:
                raise ReadCredentialUsecaseError("Credential not found")
        return credential
