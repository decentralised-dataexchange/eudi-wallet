import uuid
from logging import Logger
from time import time
from typing import Optional

from mnemonic import Mnemonic

from eudi_wallet.ebsi.models.organisation import OrganisationModel
from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository
from eudi_wallet.ebsi.value_objects.application.organisation import OrganisationRoles


class RegisterOrganisationUsecase:
    def __init__(
        self, organisation_repository: SqlAlchemyOrganisationRepository, logger: Logger
    ) -> None:
        self.organisation_repository = organisation_repository
        self.logger = logger

    def execute(
        self,
        name: str,
        description: Optional[str] = None,
        logo_url: Optional[str] = None,
    ) -> OrganisationModel:
        # Create an organistion in db
        with self.organisation_repository as repo:
            mnemo = Mnemonic("english")
            seed_phrase = mnemo.generate(strength=256)
            # cryptographic_seed = str(time.time())
            return repo.create(
                name=name,
                cryptographic_seed=seed_phrase,
                description=description,
                logo_url=logo_url,
                role=OrganisationRoles.Issuer.value,
            )
