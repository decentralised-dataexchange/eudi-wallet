from logging import Logger
from typing import Optional

from eudi_wallet.ebsi.models.organisation import OrganisationModel
from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository


class UpdateOrganisationUsecase:
    def __init__(
        self, organisation_repository: SqlAlchemyOrganisationRepository, logger: Logger
    ) -> None:
        self.organisation_repository = organisation_repository
        self.logger = logger

    def execute(
        self,
        organisation_id: str,
        name: str,
        description: Optional[str] = None,
        logo_url: Optional[str] = None,
    ) -> OrganisationModel:
        # Update an organisation
        with self.organisation_repository as repo:
            return repo.update(
                organisation_id,
                name=name,
                description=description,
                logo_url=logo_url,
            )
