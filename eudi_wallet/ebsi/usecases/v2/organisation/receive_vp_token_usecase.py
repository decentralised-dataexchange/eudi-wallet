from logging import Logger
from typing import Tuple, Optional
from eudi_wallet.ebsi.models.v2.verification_record import VerificationRecordModel
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)
from eudi_wallet.ebsi.value_objects.domain.verification import VerificationRecordStatus

from sdjwt.pex import (
    decode_header_and_claims_in_jwt,
    validate_vp_token_against_presentation_submission_and_presentation_definition,
    UnSupportedSignatureAlgorithmError,
    VpTokenExpiredError,
    PresentationSubmissionValidationError,
    PresentationDefinitionValidationError,
)
from eudi_wallet.ebsi.utils.webhook import send_webhook


class ReceiveVpTokenUsecase:
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
        state: str,
        vp_token: str,
        presentation_submission: dict,
        webhook_url: Optional[str] = None,
    ) -> Tuple[VerificationRecordModel]:
        with self.repository as repo:
            verification_record = repo.get_by_vp_token_request_state(
                vp_token_request_state=state
            )
            assert verification_record is not None

            _, claims = decode_header_and_claims_in_jwt(
                verification_record.vp_token_request
            )

            try:
                validate_vp_token_against_presentation_submission_and_presentation_definition(
                    vp_token=vp_token,
                    presentation_definition=claims.get("presentation_definition"),
                    presentation_submission=presentation_submission,
                )
            except (
                VpTokenExpiredError,
                UnSupportedSignatureAlgorithmError,
                PresentationSubmissionValidationError,
                PresentationDefinitionValidationError,
            ):
                verification_record = repo.update(
                    id=verification_record.id,
                    organisationId=organisation_id,
                    status=VerificationRecordStatus.PresentationAck.value,
                    vp_token_response=vp_token,
                    presentationSubmission=presentation_submission,
                    verified=False,
                )

                if webhook_url:
                    try:
                        send_webhook(
                            webhook_url,
                            verification_record.to_dict(),
                            topic="/topic/present_proof/"
                        )
                    except Exception:
                        self.logger.error("Exception occurred during sending webhook")
                return verification_record

            verification_record = repo.update(
                id=verification_record.id,
                organisationId=organisation_id,
                status=VerificationRecordStatus.PresentationAck.value,
                vp_token_response=vp_token,
                presentationSubmission=presentation_submission,
                verified=True,
            )

            if webhook_url:
                try:
                    send_webhook(
                        webhook_url,
                        verification_record.to_dict(),
                        topic="/topic/present_proof/"
                    )
                except Exception:
                    self.logger.error("Exception occurred during sending webhook")

        return verification_record
