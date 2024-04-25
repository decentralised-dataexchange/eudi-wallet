from logging import Logger


from eudi_wallet.ebsi.models.organisation import OrganisationModel
from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository


class ReadOrganisationUsecase:
    def __init__(
        self, organisation_repository: SqlAlchemyOrganisationRepository, logger: Logger
    ) -> None:
        self.organisation_repository = organisation_repository
        self.logger = logger

    def execute(
        self,
        id: str,
    ) -> OrganisationModel:
        # Read an organistion in db
        with self.organisation_repository as repo:

            return repo.get_by_id(
                id=id,
            )
