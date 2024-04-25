from logging import Logger
from typing import Optional

from eudi_wallet.ebsi.repositories.v2.data_agreement import (
    SqlAlchemyV2DataAgreementRepository,
)

class V2DeleteDataAgreementUsecase:
    def __init__(
        self,
        dataagreement_repository: SqlAlchemyV2DataAgreementRepository,
        logger: Optional[Logger],
    ) -> None:
        self.dataagreement_repository = dataagreement_repository
        self.logger = logger

    def execute(
        self,
        organisation_id: str,
        data_agreement_id: str,
    ) -> bool:
        with self.dataagreement_repository as repo:
            return repo.delete_by_organisation_id(
                id=data_agreement_id,
                organisation_id=organisation_id,
            )
