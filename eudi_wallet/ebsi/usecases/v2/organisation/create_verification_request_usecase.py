from logging import Logger
from typing import Optional, Tuple
import time
import uuid
import json
from eudi_wallet.did_key import KeyDid
from eudi_wallet.ebsi.models.v2.data_agreement import V2DataAgreementModel
from eudi_wallet.ebsi.repositories.v2.verification_record import (
    SqlAlchemyVerificationRecordRepository,
)
from eudi_wallet.ebsi.value_objects.domain.verification import VerificationRecordStatus
import urllib.parse
from jwcrypto import jwk, jwt
from eudi_wallet.ebsi.utils.webhook import send_webhook


class CreateVerificationRequestUsecase:
    def __init__(
        self,
        repository: SqlAlchemyVerificationRecordRepository,
        logger: Logger,
    ) -> None:
        self.repository = repository
        self.logger = logger

    def _get_alg_for_key(self, key: jwk.JWK):
        if key.key_curve == "P-256":
            alg = "ES256"
        else:
            alg = "ES256K"
        return alg

    def _create_vp_token_request(
        self,
        state: str,
        iss: str,
        aud: str,
        exp: int,
        response_type: str,
        response_mode: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        nonce: str,
        key_id: str,
        key: jwk.JWK,
        presentation_definition: dict,
    ) -> str:
        header = {"typ": "JWT", "alg": self._get_alg_for_key(key), "kid": key_id}
        payload = {
            "state": state,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "response_mode": response_mode,
            "scope": scope,
            "nonce": nonce,
            "iss": iss,
            "aud": aud,
            "exp": exp,
            "presentation_definition": presentation_definition,
        }
        token = jwt.JWT(header=header, claims=payload)
        token.make_signed_token(key)
        return token.serialize()

    def execute(
        self,
        key_did: KeyDid,
        domain: str,
        organisation_id: str,
        presentation_definition: Optional[dict] = None,
        requestByReference: bool = False,
        webhook_url: Optional[str] = None,
    ) -> Tuple[str, V2DataAgreementModel]:
        state = str(uuid.uuid4())
        iss = domain
        exp = int(time.time()) + 3600
        response_type = "vp_token"
        response_mode = "direct_post"
        client_id = f"{domain}/organisation/{organisation_id}/service"
        redirect_uri = f"{domain}/organisation/{organisation_id}/service/direct_post"
        scope = "openid"
        nonce = str(uuid.uuid4())
        key_id = f"{key_did.did}#{key_did._method_specific_id}"
        vp_token_request = self._create_vp_token_request(
            state=state,
            iss=iss,
            aud=client_id,
            exp=exp,
            response_type=response_type,
            response_mode=response_mode,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            key_id=key_id,
            key=key_did._key,
            presentation_definition=presentation_definition,
        )

        verification_record_id = str(uuid.uuid4())
        if requestByReference:
            encoded_params = urllib.parse.urlencode(
                {
                    "request_uri": f"{domain}/organisation/{organisation_id}/service/verification/{verification_record_id}",
                }
            )
        else:
            encoded_params = urllib.parse.urlencode(
                {
                    "client_id": client_id,
                    "response_type": response_type,
                    "scope": scope,
                    "redirect_uri": redirect_uri,
                    "request_uri": f"{domain}/organisation/{organisation_id}/service/verification/{verification_record_id}",
                    "response_mode": response_mode,
                    "state": state,
                    "nonce": nonce,
                    "presentation_definition": json.dumps(presentation_definition),
                }
            )
        redirection_url = f"openid4vp://?{encoded_params}"

        # Create verification record
        with self.repository as repo:
            verification_record = repo.create(
                id=verification_record_id,
                organisation_id=organisation_id,
                status=VerificationRecordStatus.RequestSent.value,
                vp_token_request_state=state,
                vp_token_request=vp_token_request,
                vp_token_qr_code=redirection_url,
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

        return redirection_url, verification_record
