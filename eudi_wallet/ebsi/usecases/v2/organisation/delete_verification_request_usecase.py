from logging import Logger
from eudi_wallet.ebsi.models.v2.verification_record import VerificationRecordModel
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)


class DeleteVerificationRequestUsecaseError(Exception):
    pass


class DeleteVerificationRequestUsecase:
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
        verification_record_id: str,
    ) -> VerificationRecordModel:
        with self.repository as repo:
            is_deleted = repo.delete(
                id=verification_record_id, organisation_id=organisation_id
            )
            if not is_deleted:
                raise DeleteVerificationRequestUsecaseError(
                    "Verification record is not deleted"
                )
        return is_deleted
