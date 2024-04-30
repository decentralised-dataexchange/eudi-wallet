from logging import Logger
from eudi_wallet.ebsi.models.v2.verification_record import VerificationRecordModel
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)


class ReadVerificationRequestUsecaseError(Exception):
    pass


class ReadVerificationRequestUsecase:
    def __init__(
        self,
        repository: SqlAlchemyVerificationRecordRepository,
        logger: Logger,
    ) -> None:
        self.repository = repository
        self.logger = logger

    def execute(
        self,
        verification_record_id: str,
    ) -> VerificationRecordModel:
        with self.repository as repo:
            verification_record = repo.get_by_id(id=verification_record_id)
            if verification_record is None:
                raise ReadVerificationRequestUsecaseError(
                    "Verification record not found"
                )
        return verification_record
