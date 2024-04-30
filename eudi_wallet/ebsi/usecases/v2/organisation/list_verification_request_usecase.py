from logging import Logger
from typing import List
from eudi_wallet.ebsi.models.v2.verification_record import VerificationRecordModel
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)


class ListVerificationRequestUsecase:
    def __init__(
        self,
        repository: SqlAlchemyVerificationRecordRepository,
        logger: Logger,
    ) -> None:
        self.repository = repository
        self.logger = logger

    def execute(
        self,
        organisation_id: str,
    ) -> List[VerificationRecordModel]:
        with self.repository as repo:
            verification_records = repo.get_all_by_organisation_id(
                organisation_id=organisation_id
            )
        return verification_records
