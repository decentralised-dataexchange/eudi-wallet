import json
from logging import Logger
from eudi_wallet.ebsi.models.v2.credential import CredentialModel
from eudi_wallet.ebsi.repositories.v2.credential import (
    SqlAlchemyCredentialRepository,
)
from pydantic import BaseModel, HttpUrl, ValidationError
from eudi_wallet.ebsi.value_objects.domain.credential import CredentialRecordStatus
from typing import Tuple, Optional
from eudi_wallet.ebsi.utils.webhook import send_webhook
from eudi_wallet.siop_auth.util import (
    send_deferred_credential_request,
)
from eudi_wallet.ebsi.exceptions.domain.issuer import (
    CredentialPendingError,
)
from aiohttp.client_exceptions import ContentTypeError
from eudi_wallet.ebsi.repositories.v2.issue_credential_record import (
    SqlAlchemyIssueCredentialRecordRepository,
)
from sdjwt.sdjwt import (
    decode_credential_sd_to_credential_subject,
    get_all_disclosures_with_sd_from_token,
)
from sdjwt.pex import decode_header_and_claims_in_jwt


class ReceiveDeferredCredentialUsecaseError(Exception):
    pass


class ReceiveDeferredCredentialUsecase:
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
        credential_id: str,
        organisation_id: str,
        webhook_url: Optional[str] = None,
    ) -> CredentialModel:
        with self.repository as repo:
            credential = repo.get_by_organisation_id_and_credential_id(
                organisation_id=organisation_id,
                credential_id=credential_id,
            )

            with self.issue_credential_repository as issue_credential_repo:
                credential_history = issue_credential_repo.get_by_id(
                    id=credential.credentialExchangeId
                )
                assert credential_history is not None

            try:
                assert (
                    credential.acceptanceToken is not None
                ), "Acceptance token is empty"
                assert (
                    credential.credentialToken is None
                ), "Credential token is already issued"
                assert (
                    credential.deferredEndpoint is not None
                ), "Deferred endpoint is empty"

                credential_response = await send_deferred_credential_request(
                    credential.deferredEndpoint, credential.acceptanceToken
                )
                status = CredentialRecordStatus.Acknowledged.value
                credential_token = credential_response["credential"]
                if credential_history.disclosureMapping:
                    credential_decoded = self.get_credential_subject_from_token(
                        credential_token
                    )
                else:
                    _, credential_decoded = decode_header_and_claims_in_jwt(
                        credential_token
                    )

                credential = repo.update(
                    id=credential.id,
                    credentialToken=credential_token,
                    credential=credential_decoded,
                    credentialStatus=status,
                )

            except ValidationError as e:
                raise ReceiveDeferredCredentialUsecaseError(json.dumps(e.errors()))
            except CredentialPendingError as e:
                return credential
            except ContentTypeError as e:
                return credential
            except AssertionError as e:
                raise ReceiveDeferredCredentialUsecaseError(e)

            if webhook_url:
                try:
                    send_webhook(
                        webhook_url, credential.to_dict(), topic="/topic/credential/"
                    )
                except Exception:
                    self.logger.error("Exception occurred during sending webhook")

            return credential
