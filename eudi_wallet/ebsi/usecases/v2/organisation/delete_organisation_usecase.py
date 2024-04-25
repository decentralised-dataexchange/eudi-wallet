from logging import Logger

from eudi_wallet.ebsi.models.organisation import OrganisationModel
from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository


class DeleteOrganisationUsecase:
    def __init__(
        self, organisation_repository: SqlAlchemyOrganisationRepository, logger: Logger
    ) -> None:
        self.organisation_repository = organisation_repository
        self.logger = logger

    def execute(
        self,
        id: str,
    ) -> OrganisationModel:
        # Delete an organistion in db
        with self.organisation_repository as repo:
            return repo.delete(
                id=id,
            )
