from logging import Logger
from typing import Optional
from eudi_wallet.ebsi.models.v2.verification_record import VerificationRecordModel
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)
from eudi_wallet.ebsi.utils.webhook import send_webhook
from eudi_wallet.ebsi.value_objects.domain.verification import VerificationRecordStatus

class ReadVerificationRequestByReferenceUsecaseError(Exception):
    pass


class ReadVerificationRequestByReferenceUsecase:
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
        webhook_url: Optional[str] = None,
    ) -> VerificationRecordModel:
        with self.repository as repo:
            verification_record = repo.get_by_id(id=verification_record_id)
            if verification_record is None:
                raise ReadVerificationRequestByReferenceUsecaseError(
                    "Verification request not found"
                )

            verification_record = repo.update(
                id=verification_record.id,
                status=VerificationRecordStatus.RequestReceived.value,
            )

            if webhook_url:
                try:
                    send_webhook(
                        webhook_url,
                        verification_record.to_dict(),
                        topic="/topic/present_proof/",
                    )
                except Exception:
                    self.logger.error("Exception occurred during sending webhook")
        return verification_record
