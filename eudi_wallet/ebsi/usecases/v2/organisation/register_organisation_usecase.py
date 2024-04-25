import time

# import uuid
from logging import Logger
from typing import Optional

from eudi_wallet.ebsi.models.organisation import OrganisationModel
from eudi_wallet.ebsi.repositories.organisation import SqlAlchemyOrganisationRepository
from eudi_wallet.ebsi.value_objects.application.organisation import OrganisationRoles

# from mnemonic import Mnemonic


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
        cover_image_url: Optional[str] = None,
        webhook_url: Optional[str] = None,
        location: Optional[str] = None,
    ) -> OrganisationModel:
        # Create an organistion in db
        with self.organisation_repository as repo:
            # mnemo = Mnemonic("english")
            # seed_phrase = mnemo.generate(strength=256)
            cryptographic_seed = str(time.time())
            return repo.create(
                name=name,
                cryptographic_seed=cryptographic_seed,
                description=description,
                logo_url=logo_url,
                role=OrganisationRoles.Issuer.value,
                cover_image_url=cover_image_url,
                webhook_url=webhook_url,
                location=location,
            )
