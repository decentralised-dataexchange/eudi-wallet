from logging import Logger
from typing import List

from eudi_wallet.ebsi.models.v2.data_agreement import V2DataAgreementModel
from eudi_wallet.ebsi.repositories.v2.data_agreement import (
    SqlAlchemyV2DataAgreementRepository,
)


class V2GetDataAgreementByIdUsecase:
    def __init__(
        self,
        dataagreement_repository: SqlAlchemyV2DataAgreementRepository,
        logger: Logger,
    ) -> None:
        self.dataagreement_repository = dataagreement_repository
        self.logger = logger

    def execute(
        self,
        organisation_id: str,
        data_agreement_id: str,
    ) -> V2DataAgreementModel:
        with self.dataagreement_repository as repo:
            return repo.get_by_id_and_organisation_id(
                organisation_id=organisation_id, id=data_agreement_id
            )
