from logging import Logger
from typing import List

from eudi_wallet.ebsi.models.data_agreement import DataAgreementModel
from eudi_wallet.ebsi.repositories.data_agreement import (
    SqlAlchemyDataAgreementRepository,
)


class ListAllDataAgreementsUsecase:
    def __init__(
        self,
        dataagreement_repository: SqlAlchemyDataAgreementRepository,
        logger: Logger,
    ) -> None:
        self.dataagreement_repository = dataagreement_repository
        self.logger = logger

    def execute(
        self,
        organisation_id: str,
    ) -> List[DataAgreementModel]:
        with self.dataagreement_repository as repo:
            return repo.get_all_by_organisation_id(
                organisation_id=organisation_id,
            )
