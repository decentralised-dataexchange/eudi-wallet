from logging import Logger
from eudi_wallet.ebsi.models.v2.credential import CredentialModel
from eudi_wallet.ebsi.repositories.v2.credential import (
    SqlAlchemyCredentialRepository,
)
from eudi_wallet.ebsi.repositories.v2.issue_credential_record import (
    SqlAlchemyIssueCredentialRecordRepository,
)
from eudi_wallet.holder.core import process_credential_offer_and_receive_credential
from pydantic import ValidationError
import json
from eudi_wallet.ebsi.value_objects.domain.credential import CredentialRecordStatus
from typing import Tuple, Optional
from eudi_wallet.ebsi.utils.webhook import send_webhook
from sdjwt.sdjwt import (
    decode_credential_sd_to_credential_subject,
    get_all_disclosures_with_sd_from_token
)
from sdjwt.pex import (
    decode_header_and_claims_in_jwt
)


class ReceiveCredentialUsecaseError(Exception):
    pass


class ReceiveCredentialUsecase:
    def __init__(
        self,
        repository: SqlAlchemyCredentialRepository,
        issue_credential_repository: SqlAlchemyIssueCredentialRecordRepository,
        logger: Logger,
    ) -> None:
        self.repository = repository
        self.issue_credential_repository = issue_credential_repository
        self.logger = logger

    def get_credential_subject_from_token(self, token: str):
        disclosure_mapping = get_all_disclosures_with_sd_from_token(token=token)
        _, credential_decoded = decode_header_and_claims_in_jwt(token)
        credential_subject = decode_credential_sd_to_credential_subject(
            disclosure_mapping=disclosure_mapping,
            credential_subject=credential_decoded.get("vc").get("credentialSubject"),
        )
        credential_decoded["vc"]["credentialSubject"] = credential_subject
        return credential_decoded

    async def execute(
        self,
        credential_offer: str,
        organisation_id: str,
        webhook_url: Optional[str] = None,
    ) -> CredentialModel:

        try:
            # Extract the credential exchange id from the credential offer
            last_slash_index = credential_offer.rfind("/")
            credential_exchange_id = credential_offer[last_slash_index + 1 :]

            with self.issue_credential_repository as issue_credential_repo:
                credential_history = issue_credential_repo.get_by_id(
                    id=credential_exchange_id
                )
                assert credential_history is not None

            (
                credential_response,
                deferred_endpoint,
            ) = await process_credential_offer_and_receive_credential(credential_offer)

            if credential_response.credential:
                status = CredentialRecordStatus.Acknowledged.value
                credential_token = credential_response.credential
                if credential_history.disclosureMapping:
                    credential_decoded = self.get_credential_subject_from_token(
                        credential_token
                    )
                else:
                    _, credential_decoded = decode_header_and_claims_in_jwt(
                        credential_token
                    )
            else:
                status = CredentialRecordStatus.Pending.value
                acceptance_token = credential_response.acceptance_token
        except ValidationError as e:
            raise ReceiveCredentialUsecaseError(json.dumps(e.errors()))
        with self.repository as repo:
            credential = repo.create(
                organisation_id=organisation_id,
                status=status,
                acceptance_token=(
                    acceptance_token if credential_response.acceptance_token else None
                ),
                credential_token=(
                    credential_token if credential_response.credential else None
                ),
                credential_token_decoded=(
                    credential_decoded if credential_response.credential else None
                ),
                credential_exchange_id=credential_exchange_id,
                deferred_endpoint=deferred_endpoint if deferred_endpoint else None,
            )
        if webhook_url:
            try:
                send_webhook(
                    webhook_url, credential.to_dict(), topic="/topic/credential/"
                )
            except Exception:
                self.logger.error("Exception occurred during sending webhook")

        return credential
