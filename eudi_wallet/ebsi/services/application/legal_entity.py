import json
import time
import urllib.parse
import uuid
from datetime import datetime
from logging import Logger
from typing import List, Optional, Tuple, Union

from eth_account import Account
from eth_account.signers.local import LocalAccount
from jwcrypto import jwk, jwt
from jwcrypto.common import json_decode

from eudi_wallet.ebsi.entities.application.credential_offer import \
    CredentialOfferEntity
from eudi_wallet.ebsi.entities.application.credential_revocation_status_list import \
    CredentialRevocationStatusListEntity
from eudi_wallet.ebsi.entities.application.credential_schema import \
    CredentialSchemaEntity
from eudi_wallet.ebsi.entities.application.legal_entity import \
    LegalEntityEntity
from eudi_wallet.ebsi.exceptions.application.legal_entity import (
    ClientIdRequiredError, CreateAccessTokenError, CreateCredentialOfferError,
    CredentialOfferIsPreAuthorizedError, CredentialOfferNotFoundError,
    InvalidAuthorisationCodeError, InvalidClientError,
    InvalidCodeVerifierError, InvalidPreAuthorisedCodeError,
    InvalidStateInIDTokenResponseError, InvalidUserPinError,
    StatusListNotFoundError, UpdateCredentialOfferError, UserPinRequiredError,
    ValidateDataAttributeValuesAgainstDataAttributesError)
from eudi_wallet.ebsi.exceptions.domain.authn import (
    InvalidAcceptanceTokenError, InvalidAccessTokenError)
from eudi_wallet.ebsi.exceptions.domain.issuer import (
    CredentialOfferRevocationError, CredentialPendingError,
    CredentialRevocationStatusListNotFoundError)
from eudi_wallet.ebsi.repositories.application.credential_offer import \
    SqlAlchemyCredentialOfferRepository
from eudi_wallet.ebsi.repositories.application.credential_revocation_status_list import \
    SqlAlchemyCredentialRevocationStatusListRepository
from eudi_wallet.ebsi.repositories.application.credential_schema import \
    SqlAlchemyCredentialSchemaRepository
from eudi_wallet.ebsi.repositories.application.legal_entity import \
    SqlAlchemyLegalRepository
from eudi_wallet.ebsi.services.domain.authn import AuthnService
from eudi_wallet.ebsi.services.domain.authn_request_builder import \
    AuthorizationRequestBuilder
from eudi_wallet.ebsi.services.domain.did_registry import DIDRegistryService
from eudi_wallet.ebsi.services.domain.issuer import IssuerService
from eudi_wallet.ebsi.services.domain.ledger import LedgerService
from eudi_wallet.ebsi.services.domain.trusted_issuer_registry import TIRService
from eudi_wallet.ebsi.services.domain.utils.authn import \
    generate_code_challenge
from eudi_wallet.ebsi.services.domain.utils.credential import (
    CredentialStatus, create_credential_token, deserialize_credential_jwt,
    generate_w3c_vc_statuslist_encoded_bitstring,
    update_w3c_vc_statuslist_encoded_bitstring)
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did
from eudi_wallet.ebsi.utils.date_time import generate_ISO8601_UTC
from eudi_wallet.ebsi.utils.hex import convert_string_to_hex
from eudi_wallet.ebsi.utils.jwt import decode_header_and_claims_in_jwt
from eudi_wallet.ebsi.value_objects.application.legal_entity import \
    LegalEntityRoles
from eudi_wallet.ebsi.value_objects.domain.authn import (
    AuthorisationGrants, AuthorizationRequestQueryParams,
    CreateIDTokenResponse, TokenResponse, VerifiablePresentation,
    VpJwtTokenPayloadModel)
from eudi_wallet.ebsi.value_objects.domain.did_registry import (
    AddVerificationMethodJSONRPC20RequestBody, AddVerificationMethodParams,
    AddVerificationRelationshipJSONRPC20RequestBody,
    AddVerificationRelationshipParams, InsertDIDDocumentJSONRPC20RequestBody,
    InsertDIDDocumentParams)
from eudi_wallet.ebsi.value_objects.domain.discovery import (
    OpenIDAuthServerConfig, OpenIDCredentialIssuerConfig)
from eudi_wallet.ebsi.value_objects.domain.issuer import (
    AcceptanceTokenResponse, CredentialIssuanceModes, CredentialProof,
    CredentialRequest, CredentialRequestPayload, CredentialResponse,
    CredentialStatuses, CredentialTypes, SendCredentialRequest,
    VerifiableAccreditationToAttest)
from eudi_wallet.ebsi.value_objects.domain.ledger import (
    GetTransactionReceiptJSONRPC20RequestBody,
    SendSignedTransactionJSONRPC20RequestBody, SendSignedTransactionParams,
    ToBeSignedTransaction)
from eudi_wallet.ebsi.value_objects.domain.trusted_issuer_registry import (
    AddIssuerProxyJSONRPC20RequestBody, AddIssuerProxyParams,
    InsertIssuerJSONRPC20RequestBody, InsertIssuerParams, ProxyData,
    SetAttributeDataJSONRPC20RequestBody, SetAttributeDataParams)


class LegalEntityService:
    def __init__(
        self,
        credential_issuer_configuration: Optional[OpenIDCredentialIssuerConfig] = None,
        auth_server_configuration: Optional[OpenIDAuthServerConfig] = None,
        logger: Optional[Logger] = None,
        issuer_domain: Optional[str] = None,
        auth_domain: Optional[str] = None,
        legal_entity_repository: Optional[SqlAlchemyLegalRepository] = None,
        credential_schema_repository: Optional[
            SqlAlchemyCredentialSchemaRepository
        ] = None,
        credential_offer_repository: Optional[
            SqlAlchemyCredentialOfferRepository
        ] = None,
        credential_revocation_status_list_repository: Optional[
            SqlAlchemyCredentialRevocationStatusListRepository
        ] = None,
    ):
        self.key_did = None
        self.ebsi_did = None
        self.eth = None
        self.legal_entity_entity = None
        self.credential_issuer_configuration = credential_issuer_configuration
        self.auth_server_configuration = auth_server_configuration
        self.logger = logger
        self.issuer_domain = issuer_domain
        self.auth_domain = auth_domain
        self.legal_entity_repository = legal_entity_repository
        self.credential_schema_repository = credential_schema_repository
        self.credential_offer_repository = credential_offer_repository
        self.credential_revocation_status_list_repository = (
            credential_revocation_status_list_repository
        )
        self.crypto_seed = None

    async def set_cryptographic_seed(self, crypto_seed: str) -> None:
        self.crypto_seed = crypto_seed
        self.eth, self.ebsi_did, self.key_did = await generate_and_store_did(
            crypto_seed
        )

    async def set_entity(
        self,
        legal_entity_entity: Optional[LegalEntityEntity] = None,
    ) -> None:
        self.legal_entity_entity = legal_entity_entity

    async def create_legal_entity(
        self, cryptographic_seed: str, is_onboarding_in_progress: bool, role: str
    ) -> LegalEntityEntity:
        with self.legal_entity_repository as repo:
            return repo.create(
                cryptographic_seed=cryptographic_seed,
                is_onboarding_in_progress=is_onboarding_in_progress,
                role=role,
            )

    async def update_legal_entity(self, legal_entity_id: str, **kwargs):
        with self.legal_entity_repository as repo:
            return repo.update(legal_entity_id, **kwargs)

    async def get_access_token_for_ebsi_services(
        self,
        ebsi_auth_client: AuthnService,
        verifiableCredential: List[str],
        scope: str,
        key: jwk.JWK,
    ) -> TokenResponse:
        presentation_definition = await ebsi_auth_client.get_presentation_definition(
            scope=scope,
        )

        jti = f"urn:uuid:{str(uuid.uuid4())}"
        aud = "https://api-conformance.ebsi.eu/authorisation/v3"
        vp_token = ebsi_auth_client.create_vp_token(
            VpJwtTokenPayloadModel(
                kid=f"{self.ebsi_did.did}#{key.key_id}",
                iss=self.ebsi_did.did,
                aud=aud,
                sub=self.ebsi_did.did,
                vp=VerifiablePresentation(
                    context=["https://www.w3.org/2018/credentials/v1"],
                    id=jti,
                    type=["VerifiablePresentation"],
                    holder=self.ebsi_did.did,
                    verifiableCredential=verifiableCredential,
                ),
                jti=jti,
                nonce=str(uuid.uuid4()),
            ),
            key,
        )

        if len(presentation_definition.input_descriptors) > 0:
            presentation_submission = ebsi_auth_client.create_presentation_submission(
                presentation_definition_id=presentation_definition.id,
                descriptor_map_id=presentation_definition.input_descriptors[0].id,
            )
        else:
            presentation_submission = ebsi_auth_client.create_presentation_submission(
                presentation_definition_id=presentation_definition.id,
                descriptor_map_id=None,
            )

        vp_access_token = await ebsi_auth_client.send_vp_token(
            grant_type="vp_token",
            scope=scope,
            vp_token=vp_token,
            presentation_submission=presentation_submission.to_json(),
        )

        return vp_access_token

    async def add_verification_method(
        self,
        public_key_thumbprint: str,
        public_key_hex: str,
        did_registry_client: DIDRegistryService,
        ledger_client: LedgerService,
        eth_account_address: str,
    ):
        rpc_response = await did_registry_client.add_verification_method(
            AddVerificationMethodJSONRPC20RequestBody(
                params=[
                    AddVerificationMethodParams(
                        did=self.ebsi_did.did,
                        vMethodId=public_key_thumbprint,
                        publicKey=f"0x{public_key_hex}",
                        isSecp256k1=False,
                        _from=eth_account_address,
                    )
                ],
                id=str(uuid.uuid4()),
            )
        )

        signed_transaction = await ledger_client.sign_ledger_transaction(
            tbs=ToBeSignedTransaction(
                to=rpc_response.result.to,
                data=rpc_response.result.data,
                value=rpc_response.result.value,
                nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
                chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
                gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
                gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
            ),
            eth_private_key=self.eth.private_key,
        )

        send_signed_transaction_rpc_response = await ledger_client.send_signed_transaction(
            SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )

        self.logger.debug("Waiting for transaction to be mined...")
        transaction_receipt = await ledger_client.get_transaction_receipt(
            GetTransactionReceiptJSONRPC20RequestBody(
                params=[send_signed_transaction_rpc_response.result],
                id=str(uuid.uuid4()),
            )
        )

        self.logger.debug(
            f"Add verification method transaction: {transaction_receipt.result.transactionHash}"
        )

    async def add_verification_relationship(
        self,
        verification_relationship_name: str,
        did_registry_client: DIDRegistryService,
        ledger_client: LedgerService,
        eth_account_address: str,
    ):
        not_before = int(time.time())
        not_after = not_before + 31536000
        rpc_response = await did_registry_client.add_verification_relationship(
            AddVerificationRelationshipJSONRPC20RequestBody(
                params=[
                    AddVerificationRelationshipParams(
                        did=self.ebsi_did.did,
                        name=verification_relationship_name,
                        vMethodId=self.key_did.jwk_thumbprint,
                        notBefore=not_before,
                        notAfter=not_after,
                        _from=eth_account_address,
                    )
                ],
                id=str(uuid.uuid4()),
            )
        )

        signed_transaction = await ledger_client.sign_ledger_transaction(
            tbs=ToBeSignedTransaction(
                to=rpc_response.result.to,
                data=rpc_response.result.data,
                value=rpc_response.result.value,
                nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
                chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
                gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
                gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
            ),
            eth_private_key=self.eth.private_key,
        )

        send_signed_transaction_rpc_response = await ledger_client.send_signed_transaction(
            SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )

        self.logger.debug("Waiting for transaction to be mined...")
        transaction_receipt = await ledger_client.get_transaction_receipt(
            GetTransactionReceiptJSONRPC20RequestBody(
                params=[send_signed_transaction_rpc_response.result],
                id=str(uuid.uuid4()),
            )
        )

        self.logger.debug(
            f"Add verification relationship({verification_relationship_name}) transaction: {transaction_receipt.result.transactionHash}"
        )

    async def insert_did_document(
        self,
        did_registry_client: DIDRegistryService,
        ledger_client: LedgerService,
        eth_account_address: str,
    ):
        base_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
            ]
        }

        not_before = int(time.time())
        not_after = not_before + 31536000  # Expiry 1 year

        rpc_response = await did_registry_client.insert_did_document(
            InsertDIDDocumentJSONRPC20RequestBody(
                params=[
                    InsertDIDDocumentParams(
                        did=self.ebsi_did.did,
                        baseDocument=json.dumps(base_document),
                        vMethodId=self.eth.jwk_thumbprint,
                        publicKey=f"0x{self.eth.public_key_hex}",
                        isSecp256k1=True,
                        notBefore=not_before,
                        notAfter=not_after,
                        _from=eth_account_address,
                    )
                ],
                id=str(uuid.uuid4()),
            )
        )

        signed_transaction = await ledger_client.sign_ledger_transaction(
            tbs=ToBeSignedTransaction(
                to=rpc_response.result.to,
                data=rpc_response.result.data,
                value=rpc_response.result.value,
                nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
                chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
                gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
                gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
            ),
            eth_private_key=self.eth.private_key,
        )

        send_signed_transaction_rpc_response = await ledger_client.send_signed_transaction(
            SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )

        self.logger.debug("Waiting for transaction to be mined...")
        transaction_receipt = await ledger_client.get_transaction_receipt(
            GetTransactionReceiptJSONRPC20RequestBody(
                params=[send_signed_transaction_rpc_response.result],
                id=str(uuid.uuid4()),
            )
        )

        self.logger.debug(
            f"Insert DID document transaction: {transaction_receipt.result.transactionHash}"
        )

    async def insert_issuer(
        self,
        issuer_type: int,
        attribute_data: str,
        tao_did: str,
        tao_attribute_id: str,
        tir_client: TIRService,
        ledger_client: LedgerService,
        eth_account_address: str,
    ):
        rpc_response = await tir_client.insert_issuer(
            payload=InsertIssuerJSONRPC20RequestBody(
                params=[
                    InsertIssuerParams(
                        did=self.ebsi_did.did,
                        attributeData=attribute_data,
                        taoDid=tao_did,
                        taoAttributeId=tao_attribute_id,
                        issuerType=issuer_type,
                        _from=eth_account_address,
                    )
                ],
                id=str(uuid.uuid4()),
            )
        )

        signed_transaction = await ledger_client.sign_ledger_transaction(
            tbs=ToBeSignedTransaction(
                to=rpc_response.result.to,
                data=rpc_response.result.data,
                value=rpc_response.result.value,
                nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
                chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
                gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
                gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
            ),
            eth_private_key=self.eth.private_key,
        )

        send_signed_transaction_rpc_response = await ledger_client.send_signed_transaction(
            SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )

        self.logger.debug("Waiting for transaction to be mined...")
        transaction_receipt = await ledger_client.get_transaction_receipt(
            GetTransactionReceiptJSONRPC20RequestBody(
                params=[send_signed_transaction_rpc_response.result],
                id=str(uuid.uuid4()),
            )
        )

        self.logger.debug(
            f"Insert issuer transaction: {transaction_receipt.result.transactionHash}"
        )

    async def set_attribute_data(
        self,
        attribute_id: str,
        attribute_data: str,
        tir_client: TIRService,
        ledger_client: LedgerService,
        eth_account_address: str,
    ):
        rpc_response = await tir_client.set_attribute_data(
            payload=SetAttributeDataJSONRPC20RequestBody(
                params=[
                    SetAttributeDataParams(
                        did=self.ebsi_did.did,
                        attributeData=attribute_data,
                        attributeId=attribute_id,
                        _from=eth_account_address,
                    )
                ],
                id=str(uuid.uuid4()),
            )
        )

        signed_transaction = await ledger_client.sign_ledger_transaction(
            tbs=ToBeSignedTransaction(
                to=rpc_response.result.to,
                data=rpc_response.result.data,
                value=rpc_response.result.value,
                nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
                chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
                gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
                gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
            ),
            eth_private_key=self.eth.private_key,
        )

        send_signed_transaction_rpc_response = await ledger_client.send_signed_transaction(
            SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )

        self.logger.debug("Waiting for transaction to be mined...")
        transaction_receipt = await ledger_client.get_transaction_receipt(
            GetTransactionReceiptJSONRPC20RequestBody(
                params=[send_signed_transaction_rpc_response.result],
                id=str(uuid.uuid4()),
            )
        )

        self.logger.debug(
            f"Set attribute data transaction: {transaction_receipt.result.transactionHash}"
        )

    async def add_issuer_proxy(
        self,
        proxy_data: str,
        tir_client: TIRService,
        ledger_client: LedgerService,
        eth_account_address: str,
    ):
        rpc_response = await tir_client.add_issuer_proxy(
            payload=AddIssuerProxyJSONRPC20RequestBody(
                params=[
                    AddIssuerProxyParams(
                        did=self.ebsi_did.did,
                        proxyData=proxy_data,
                        _from=eth_account_address,
                    )
                ],
                id=str(uuid.uuid4()),
            )
        )

        signed_transaction = await ledger_client.sign_ledger_transaction(
            tbs=ToBeSignedTransaction(
                to=rpc_response.result.to,
                data=rpc_response.result.data,
                value=rpc_response.result.value,
                nonce=int(rpc_response.result.nonce.replace("0x", ""), 16),
                chainId=int(rpc_response.result.chainId.replace("0x", ""), 16),
                gas=int(rpc_response.result.gasLimit.replace("0x", ""), 16),
                gasPrice=int(rpc_response.result.gasPrice.replace("0x", ""), 16),
            ),
            eth_private_key=self.eth.private_key,
        )

        send_signed_transaction_rpc_response = await ledger_client.send_signed_transaction(
            SendSignedTransactionJSONRPC20RequestBody(
                params=[
                    SendSignedTransactionParams(
                        protocol="eth",
                        unsignedTransaction=rpc_response.result.to_dict(),
                        r=hex(signed_transaction.r),
                        s=hex(signed_transaction.s),
                        v=hex(signed_transaction.v),
                        signedRawTransaction=signed_transaction.rawTransaction.hex(),
                    )
                ],
                id=str(uuid.uuid4()),
                method="sendSignedTransaction",
            )
        )

        self.logger.debug("Waiting for transaction to be mined...")
        transaction_receipt = await ledger_client.get_transaction_receipt(
            GetTransactionReceiptJSONRPC20RequestBody(
                params=[send_signed_transaction_rpc_response.result],
                id=str(uuid.uuid4()),
            )
        )

        self.logger.debug(
            f"Add issuer proxy transaction: {transaction_receipt.result.transactionHash}"
        )

    async def get_legal_entity_onboarding_credential(
        self,
        credential_types: List[str],
        auth_mock_client: AuthnService,
        iss_mock_client: IssuerService,
    ) -> CredentialResponse:
        auth_req_builder = AuthorizationRequestBuilder(
            iss=self.issuer_domain,
            aud=self.credential_issuer_configuration.authorization_server,
            response_type="code",
            scope="openid",
            client_id=self.issuer_domain,
            redirect_uri=self.issuer_domain + "/auth-redirect",
        )
        auth_req_builder.set_client_metadata(jwks_uri=self.issuer_domain + "/jwks")
        auth_req_builder.set_authorization_details(
            locations=[self.credential_issuer_configuration.credential_issuer],
            types=credential_types,
        )
        auth_req = auth_req_builder.build_authorization_request()
        auth_req_token = auth_mock_client.create_authorization_request(
            auth_req, self.key_did._key.key_id, self.key_did._key
        )

        id_token_request = await auth_mock_client.send_authorization_request(
            client_id=self.issuer_domain,
            scope="openid",
            redirect_uri=self.issuer_domain + "/auth-redirect",
            request=auth_req_token,
            nonce=auth_req_builder.nonce,
        )

        id_token_request_jwt = await auth_mock_client.get_id_token_request_jwt(
            id_token_request.request_uri
        )

        id_token_response_jwt = auth_mock_client.create_id_token_response(
            CreateIDTokenResponse(
                kid=f"{self.ebsi_did.did}#{self.key_did._key.key_id}",
                iss=self.ebsi_did.did,
                sub=self.ebsi_did.did,
                aud=self.credential_issuer_configuration.authorization_server,
                nonce=id_token_request_jwt.nonce,
                state=id_token_request_jwt.state,
            ),
            self.key_did._key,
        )
        auth_code_redirect_uri_response = await auth_mock_client.send_id_token_response(
            id_token_request.redirect_uri,
            id_token_response_jwt.token,
            id_token_request_jwt.state,
        )

        client_assertion_jwt = auth_mock_client.create_client_assertion(
            kid=self.key_did.public_key_jwk.get("kid"),
            iss=self.issuer_domain,
            sub=self.issuer_domain,
            aud=self.credential_issuer_configuration.authorization_server,
            jti=str(uuid.uuid4()),
            key=self.key_did._key,
        )

        access_token = await auth_mock_client.send_token_request(
            token_uri=self.auth_server_configuration.token_endpoint,
            client_id=self.issuer_domain,
            code=auth_code_redirect_uri_response.code,
            client_assertion=client_assertion_jwt.token,
        )

        credential_request_jwt = iss_mock_client.create_credential_request(
            kid=f"{self.ebsi_did.did}#{self.key_did.public_key_jwk.get('kid')}",
            iss=self.issuer_domain,
            aud=self.credential_issuer_configuration.credential_issuer,
            nonce=access_token.c_nonce,
            key=self.key_did._key,
        )

        credential = await iss_mock_client.send_credential_request(
            SendCredentialRequest(
                credential_uri=self.credential_issuer_configuration.credential_endpoint,
                token=access_token.access_token,
                payload=CredentialRequestPayload(
                    types=credential_types,
                    proof=CredentialProof(jwt=credential_request_jwt),
                ),
            )
        )

        self.logger.debug(
            f"Received credential of type {credential_types[-1]}: \n{credential.to_json(indent=4)}"
        )

        return credential

    async def fill_did_registry(self):
        auth_mock_client = AuthnService(
            authorization_endpoint=self.auth_server_configuration.authorization_endpoint,
            logger=self.logger,
        )
        iss_mock_client = IssuerService(
            self.credential_issuer_configuration.credential_endpoint,
            logger=self.logger,
        )
        ebsi_auth_client = AuthnService(
            presentation_definition_endpoint="https://api-conformance.ebsi.eu/authorisation/v3/presentation-definitions",
            token_endpoint="https://api-conformance.ebsi.eu/authorisation/v3/token",
            logger=self.logger,
        )
        ledger_client = LedgerService(
            registry_rpc_endpoint="https://api-conformance.ebsi.eu/did-registry/v4/jsonrpc",
            besu_rpc_endpoint="https://api-conformance.ebsi.eu/ledger/v3/blockchains/besu",
            logger=self.logger,
        )
        did_registry_client = DIDRegistryService(
            did_registry_rpc_endpoint="https://api-conformance.ebsi.eu/did-registry/v4/jsonrpc",
            besu_rpc_endpoint="https://api-conformance.ebsi.eu/ledger/v3/blockchains/besu",
            logger=self.logger,
        )

        credential_types = [
            CredentialTypes.VerifiableCredential.value,
            CredentialTypes.VerifiableAttestation.value,
            CredentialTypes.VerifiableAuthorisationToOnboard.value,
        ]

        credential = await self.get_legal_entity_onboarding_credential(
            credential_types=credential_types,
            auth_mock_client=auth_mock_client,
            iss_mock_client=iss_mock_client,
        )

        with self.legal_entity_repository as repo:
            # Save credential to repository
            self.legal_entity_entity = repo.update(
                id=self.legal_entity_entity.id,
                verifiable_authorisation_to_onboard=credential.credential,
            )

        vp_access_token = await self.get_access_token_for_ebsi_services(
            ebsi_auth_client=ebsi_auth_client,
            verifiableCredential=[credential.credential],
            scope="openid+didr_invite",
            key=self.key_did._key,
        )

        ledger_client.set_access_token(vp_access_token.access_token)
        did_registry_client.set_access_token(vp_access_token.access_token)

        local_account: LocalAccount = Account.from_key(self.eth.private_key)  # type: ignore
        account_address = local_account.address

        await self.insert_did_document(
            did_registry_client=did_registry_client,
            ledger_client=ledger_client,
            eth_account_address=account_address,
        )

        vp_access_token = await self.get_access_token_for_ebsi_services(
            ebsi_auth_client=ebsi_auth_client,
            verifiableCredential=[credential.credential],
            scope="openid+didr_write",
            key=self.eth.private_key_jwk,
        )

        did_registry_client.set_access_token(vp_access_token.access_token)
        ledger_client.set_access_token(vp_access_token.access_token)
        local_account: LocalAccount = Account.from_key(self.eth.private_key)  # type: ignore
        account_address = local_account.address

        await self.add_verification_method(
            public_key_thumbprint=self.key_did.jwk_thumbprint,
            public_key_hex=self.key_did.public_key_hex,
            did_registry_client=did_registry_client,
            ledger_client=ledger_client,
            eth_account_address=account_address,
        )

        await self.add_verification_relationship(
            verification_relationship_name="authentication",
            did_registry_client=did_registry_client,
            ledger_client=ledger_client,
            eth_account_address=account_address,
        )

        await self.add_verification_relationship(
            verification_relationship_name="assertionMethod",
            did_registry_client=did_registry_client,
            ledger_client=ledger_client,
            eth_account_address=account_address,
        )

    async def fill_trusted_issuer_registry(self):
        auth_mock_client = AuthnService(
            authorization_endpoint=self.auth_server_configuration.authorization_endpoint,
            logger=self.logger,
        )
        iss_mock_client = IssuerService(
            self.credential_issuer_configuration.credential_endpoint,
            logger=self.logger,
        )
        ebsi_auth_client = AuthnService(
            presentation_definition_endpoint="https://api-conformance.ebsi.eu/authorisation/v3/presentation-definitions",
            token_endpoint="https://api-conformance.ebsi.eu/authorisation/v3/token",
            logger=self.logger,
        )
        ledger_client = LedgerService(
            registry_rpc_endpoint="https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/jsonrpc",
            besu_rpc_endpoint="https://api-conformance.ebsi.eu/ledger/v3/blockchains/besu",
            logger=self.logger,
        )
        tir_client = TIRService(
            trusted_issuer_registry_rpc_endpoint="https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/jsonrpc",
            logger=self.logger,
        )

        credential_types = [
            CredentialTypes.VerifiableCredential.value,
            CredentialTypes.VerifiableAttestation.value,
            CredentialTypes.VerifiableAccreditationToAttest.value,
        ]

        credential = await self.get_legal_entity_onboarding_credential(
            credential_types=credential_types,
            auth_mock_client=auth_mock_client,
            iss_mock_client=iss_mock_client,
        )

        with self.legal_entity_repository as repo:
            # Save credential to repository
            self.legal_entity_entity = repo.update(
                id=self.legal_entity_entity.id,
                verifiable_accreditation_to_attest=credential.credential,
            )

        verifiable_accreditation_to_attest: VerifiableAccreditationToAttest = (
            deserialize_credential_jwt(credential_jwt=credential.credential)
        )

        vp_access_token = await self.get_access_token_for_ebsi_services(
            ebsi_auth_client=ebsi_auth_client,
            verifiableCredential=[credential.credential],
            scope="openid+tir_invite",
            key=self.key_did._key,
        )

        ledger_client.set_access_token(vp_access_token.access_token)
        tir_client.set_access_token(vp_access_token.access_token)

        local_account: LocalAccount = Account.from_key(self.eth.private_key)  # type: ignore
        account_address = local_account.address
        await self.set_attribute_data(
            attribute_id=verifiable_accreditation_to_attest.credentialSubject.reservedAttributeId,
            attribute_data=f"0x{convert_string_to_hex(credential.credential)}",
            tir_client=tir_client,
            ledger_client=ledger_client,
            eth_account_address=account_address,
        )

        vp_access_token = await self.get_access_token_for_ebsi_services(
            ebsi_auth_client=ebsi_auth_client,
            verifiableCredential=[credential.credential],
            scope="openid+tir_write",
            key=self.key_did._key,
        )

        ledger_client.set_access_token(vp_access_token.access_token)
        tir_client.set_access_token(vp_access_token.access_token)

        proxy_data = ProxyData(
            prefix=self.issuer_domain,
            headers={},
            testSuffix="/credentials/status/1",
        )
        await self.add_issuer_proxy(
            proxy_data=json.dumps(proxy_data.to_dict(), separators=(",", ":")),
            tir_client=tir_client,
            ledger_client=ledger_client,
            eth_account_address=account_address,
        )

    async def onboard_trusted_issuer(self):
        assert self.legal_entity_entity, "Legal entity not found"

        try:
            await self.fill_did_registry()
            await self.fill_trusted_issuer_registry()

            with self.legal_entity_repository as repo:
                self.legal_entity_entity = repo.update(
                    id=self.legal_entity_entity.id,
                    is_onboarding_in_progress=False,
                    is_onboarded=True,
                )
        except Exception as e:
            self.logger.debug(f"Error onboarding trusted issuer: {e}")
            with self.legal_entity_repository as repo:
                self.legal_entity_entity = repo.update(
                    id=self.legal_entity_entity.id,
                    is_onboarding_in_progress=False,
                    is_onboarded=False,
                    cryptographic_seed=f"{int(time.time())}",
                )

    def _create_credential_token(
        self,
        credential_issuer: str,
        credential_id: str,
        credential_type: List[str],
        credential_context: List[str],
        credential_subject: dict,
        credential_schema: Union[dict, List[dict]],
        jti: str,
        iss: str,
        sub: str,
        kid: str,
        key: jwk.JWK,
        credential_status: Optional[dict] = None,
        terms_of_use: Optional[Union[dict, List[dict]]] = None,
    ) -> str:
        seconds_in_one_year = 31536000
        iss_in_epoch, issuance_date = generate_ISO8601_UTC()
        exp_in_epoch, expiration_date = generate_ISO8601_UTC(seconds_in_one_year)
        vc = {
            "@context": credential_context,
            "id": credential_id,
            "type": credential_type,
            "issuer": credential_issuer,
            "issuanceDate": issuance_date,
            "validFrom": issuance_date,
            "expirationDate": expiration_date,
            "issued": issuance_date,
            "credentialSubject": credential_subject,
            "credentialSchema": credential_schema,
        }
        if credential_status:
            vc["credentialStatus"] = credential_status

        if terms_of_use:
            vc["termsOfUse"] = terms_of_use

        return create_credential_token(
            vc=vc,
            jti=jti,
            sub=sub,
            iss=iss,
            kid=kid,
            key=key,
            iat=iss_in_epoch,
            exp=exp_in_epoch,
        )

    async def issue_deferred_credential(
        self,
        acceptance_token: Optional[str] = None,
    ) -> dict:
        if not acceptance_token:
            raise InvalidAcceptanceTokenError(
                "Acceptance token is required to issue deferred credential"
            )

        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_acceptance_token(acceptance_token)
            if not credential_offer_entity:
                raise CredentialOfferNotFoundError("Credential offer not found")

            credential_schema_entity: CredentialSchemaEntity = (
                credential_offer_entity.credential_schema
            )

            if (
                credential_offer_entity.credential_status
                == CredentialStatuses.Pending.value
            ):
                raise CredentialPendingError("Credential is not available yet")

            credential_id = f"urn:did:{credential_offer_entity.id}"
            credential_type = [
                "VerifiableCredential",
                "VerifiableAttestation",
                credential_schema_entity.credential_type,
            ]
            credential_context = ["https://www.w3.org/2018/credentials/v1"]
            credential_schema = [
                {
                    "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                    "type": "FullJsonSchemaValidator2021",
                }
            ]
            credential_subject = json.loads(
                credential_offer_entity.data_attribute_values
            )
            credential_subject["id"] = credential_offer_entity.client_id
            kid = f"{self.key_did.did}#{self.key_did._method_specific_id}"
            jti = credential_id
            iss = self.key_did.did
            sub = credential_offer_entity.client_id
            to_be_issued_credential = self._create_credential_token(
                credential_id=credential_id,
                credential_type=credential_type,
                credential_context=credential_context,
                credential_subject=credential_subject,
                credential_status=None,
                terms_of_use=None,
                credential_schema=credential_schema,
                kid=kid,
                jti=jti,
                iss=iss,
                sub=sub,
                key=self.key_did._key,
                credential_issuer=self.key_did.did,
            )

            credential_response = CredentialResponse(
                format="jwt_vc", credential=to_be_issued_credential
            )

            return credential_response.to_dict()

    async def issue_credential(
        self,
        credential_request_proof_jwt: str,
        credential_type_to_be_issued: str,
        access_token: Optional[str] = None,
    ) -> dict:
        assert self.legal_entity_entity, "Legal entity not found"
        assert self.credential_offer_repository, "Credential offer repository not found"

        available_credential_types = [
            available_credential_type.value
            for available_credential_type in CredentialTypes
        ]

        decoded_credential_request_proof_jwt = decode_header_and_claims_in_jwt(
            credential_request_proof_jwt
        )

        if credential_type_to_be_issued in available_credential_types:
            with self.credential_offer_repository as repo:
                decoded_claims = decode_header_and_claims_in_jwt(access_token)

                credential_offer_id = decoded_claims.claims.get("credential_offer_id")
                credential_offer_entity = repo.get_by_id(credential_offer_id)
                if not credential_offer_entity:
                    raise InvalidAccessTokenError(
                        f"Invalid access token {access_token}"
                    )

                credential_schema_entity: CredentialSchemaEntity = (
                    credential_offer_entity.credential_schema
                )

            assert (
                self.legal_entity_entity.verifiable_accreditation_to_attest
            ), "Verifiable accreditation to attest not found"

            credential_subject = {
                "id": decoded_credential_request_proof_jwt.headers["kid"].split("#")[0]
            }

            vc_to_attest: VerifiableAccreditationToAttest = deserialize_credential_jwt(
                self.legal_entity_entity.verifiable_accreditation_to_attest
            )
            reserved_attribute_id = (
                vc_to_attest.credentialSubject.reservedAttributeId.lstrip("0x")
            )
            schema = vc_to_attest.credentialSubject.accreditedFor[0].schemaId
            proxy_id = (
                "0xdbc37e9b0c21a55faee11481ea4c346e7d45eb7c7be30728bd1063f510ff32ea"
            )

            credential_id = f"urn:did:{credential_offer_entity.id}"
            credential_type = [
                "VerifiableCredential",
                "VerifiableAttestation",
                credential_schema_entity.credential_type,
            ]
            credential_context = ["https://www.w3.org/2018/credentials/v1"]
            terms_of_use = [
                {
                    "id": f"https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/issuers/{self.ebsi_did.did}/attributes/{reserved_attribute_id}",
                    "type": "IssuanceCertificate",
                }
            ]
            credential_schema = [
                {
                    "id": schema,
                    "type": "FullJsonSchemaValidator2021",
                }
            ]
            credential_status = None
            if credential_offer_entity.supports_revocation:
                credential_status_suffix = f"/credentials/status/{credential_offer_entity.credential_revocation_status_list_id}"
                credential_status_url = f"https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/issuers/{self.ebsi_did.did}/proxies/{proxy_id}{credential_status_suffix}"
                credential_status = {
                    "id": f"{credential_status_url}#list",
                    "type": "StatusList2021Entry",
                    "statusPurpose": "revocation",
                    "statusListIndex": str(
                        credential_offer_entity.credential_revocation_status_list_index
                    ),
                    "statusListCredential": credential_status_url,
                }
            kid = f"{self.ebsi_did.did}#{self.key_did._key.key_id}"
            jti = credential_id
            iss = self.ebsi_did.did
            sub = decoded_credential_request_proof_jwt.headers["kid"].split("#")[0]
            to_be_issued_credential = self._create_credential_token(
                credential_id=credential_id,
                credential_type=credential_type,
                credential_context=credential_context,
                credential_subject=credential_subject,
                credential_status=credential_status,
                terms_of_use=terms_of_use,
                credential_schema=credential_schema,
                kid=kid,
                jti=jti,
                iss=iss,
                sub=sub,
                key=self.key_did._key,
                credential_issuer=self.ebsi_did.did,
            )

            credential_response = CredentialResponse(
                format="jwt_vc", credential=to_be_issued_credential
            )
        else:
            if not access_token:
                raise InvalidAccessTokenError(
                    f"Access token is required for credential type {credential_type_to_be_issued}"
                )

            with self.credential_offer_repository as repo:
                decoded_claims = decode_header_and_claims_in_jwt(access_token)

                credential_offer_id = decoded_claims.claims.get("credential_offer_id")
                credential_offer_entity = repo.get_by_id(credential_offer_id)
                if not credential_offer_entity:
                    raise InvalidAccessTokenError(
                        f"Invalid access token {access_token}"
                    )
                credential_schema_entity: CredentialSchemaEntity = (
                    credential_offer_entity.credential_schema
                )

                AuthnService.verify_access_token(
                    token=access_token,
                    aud=self.key_did.did,
                    sub=credential_offer_entity.client_id,
                    key=self.key_did._key,
                )

                if (
                    credential_offer_entity.issuance_mode
                    == CredentialIssuanceModes.Deferred.value
                ):
                    acceptance_token = str(uuid.uuid4())
                    credential_offer_entity = repo.update(
                        id=credential_offer_entity.id, acceptance_token=acceptance_token
                    )
                    credential_response = AcceptanceTokenResponse(
                        acceptance_token=acceptance_token
                    )
                else:
                    credential_id = f"urn:did:{credential_offer_entity.id}"
                    credential_type = [
                        "VerifiableCredential",
                        "VerifiableAttestation",
                        credential_schema_entity.credential_type,
                    ]
                    credential_context = ["https://www.w3.org/2018/credentials/v1"]
                    credential_schema = [
                        {
                            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                            "type": "FullJsonSchemaValidator2021",
                        }
                    ]
                    credential_subject = json.loads(
                        credential_offer_entity.data_attribute_values
                    )
                    credential_subject["id"] = credential_offer_entity.client_id
                    kid = f"{self.key_did.did}#{self.key_did._method_specific_id}"
                    jti = credential_id
                    iss = self.key_did.did
                    sub = credential_offer_entity.client_id
                    to_be_issued_credential = self._create_credential_token(
                        credential_id=credential_id,
                        credential_type=credential_type,
                        credential_context=credential_context,
                        credential_subject=credential_subject,
                        credential_status=None,
                        terms_of_use=None,
                        credential_schema=credential_schema,
                        kid=kid,
                        jti=jti,
                        iss=iss,
                        sub=sub,
                        key=self.key_did._key,
                        credential_issuer=self.key_did.did,
                    )

                    credential_response = CredentialResponse(
                        format="jwt_vc", credential=to_be_issued_credential
                    )

        return credential_response.to_dict()

    async def get_credential_status(self, status_list_index: str) -> dict:
        assert self.legal_entity_entity, "Legal entity not found"
        assert (
            self.legal_entity_entity.verifiable_accreditation_to_attest
        ), "Verifiable accreditation to attest not found"

        vc_to_attest: VerifiableAccreditationToAttest = deserialize_credential_jwt(
            self.legal_entity_entity.verifiable_accreditation_to_attest
        )
        # reserved_attribute_id = (
        #     vc_to_attest.credentialSubject.reservedAttributeId.lstrip("0x")
        # )
        schema = vc_to_attest.credentialSubject.accreditedFor[0].schemaId

        with self.credential_revocation_status_list_repository as revocation_repo:
            revocation_list = revocation_repo.get_by_id(status_list_index)
            if not revocation_list:
                raise CredentialRevocationStatusListNotFoundError(
                    "Status list not found"
                )

        credential_list_url = (
            f"{self.issuer_domain}/credentials/status/{status_list_index}#list"
        )

        seconds_in_one_year = 31536000
        iss_in_epoch, issuance_date = generate_ISO8601_UTC()
        exp_in_epoch, expiration_date = generate_ISO8601_UTC(seconds_in_one_year)
        status_list_vc = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vc/status-list/2021/v1",
            ],
            "id": credential_list_url,
            "type": [
                "VerifiableCredential",
                "VerifiableAttestation",
                "StatusList2021Credential",
            ],
            "issuer": self.ebsi_did.did,
            "issuanceDate": issuance_date,
            "issued": issuance_date,
            "validFrom": issuance_date,
            "expirationDate": expiration_date,
            "validUntil": expiration_date,
            "credentialSubject": {
                "id": credential_list_url,
                "type": "StatusList2021",
                "statusPurpose": "revocation",
                "encodedList": revocation_list.encoded_status_list,
            },
            "credentialSchema": [
                {
                    "id": schema,
                    "type": "FullJsonSchemaValidator2021",
                }
            ],
        }

        # terms_of_use = {
        #     "termsOfUse": {
        #         "id": f"https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/issuers/{self.ebsi_did.did}/attributes/{reserved_attribute_id}",
        #         "type": "IssuanceCertificate",
        #     },
        # }

        key = self.key_did._key
        to_be_issued_credential = create_credential_token(
            vc=status_list_vc,
            jti=credential_list_url,
            sub=credential_list_url,
            iss=self.ebsi_did.did,
            kid=f"{self.ebsi_did.did}#{key.key_id}",
            key=key,
            iat=iss_in_epoch,
            exp=exp_in_epoch,
        )
        credential_response = CredentialResponse(
            format="jwt_vc", credential=to_be_issued_credential
        )
        return credential_response.to_dict()

    async def update_revocation_status_for_credential_offer(
        self,
        credential_schema_id: str,
        credential_offer_id: str,
        is_revoked: bool,
    ) -> Union[dict, None]:
        assert self.credential_offer_repository, "Credential offer repository not found"

        with self.credential_offer_repository as offer_repo, self.credential_revocation_status_list_repository as revocation_repo:
            credential_offer_entity = offer_repo.get_by_id_and_credential_schema_id(
                credential_offer_id, credential_schema_id
            )
            if credential_offer_entity is None:
                raise CredentialOfferNotFoundError(
                    f"Credential offer with id {credential_offer_id} not found"
                )

            if not credential_offer_entity.supports_revocation:
                raise CredentialOfferRevocationError(
                    f"Credential offer with id {credential_offer_id} does not support revocation"
                )

            if (
                credential_offer_entity.credential_status
                == CredentialStatuses.Pending.value
            ):
                raise CredentialOfferRevocationError(
                    f"Credential offer with id {credential_offer_id} is in pending state"
                )

            revocation_list: CredentialRevocationStatusListEntity = (
                credential_offer_entity.credential_revocation_status_list
            )

            encoded_bitstring = update_w3c_vc_statuslist_encoded_bitstring(
                encoded_bitstring=revocation_list.encoded_status_list,
                credential_statuses=[
                    CredentialStatus(
                        status_list_index=credential_offer_entity.credential_revocation_status_list_index,
                        is_revoked=is_revoked,
                    )
                ],
            )

            credential_offer_entity = offer_repo.update(
                id=credential_offer_id, is_revoked=is_revoked
            )

            revocation_list = revocation_repo.update(
                id=credential_offer_entity.credential_revocation_status_list_id,
                encoded_status_list=encoded_bitstring,
            )

            return credential_offer_entity.to_dict()

    async def update_deferred_credential_offer_with_data_attribute_values(
        self,
        credential_schema_id: str,
        credential_offer_id: str,
        data_attribute_values: dict,
    ) -> Union[dict, None]:
        assert self.credential_offer_repository, "Credential offer repository not found"

        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_id_and_credential_schema_id(
                credential_offer_id, credential_schema_id
            )
            if credential_offer_entity is None:
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} not found"
                )

            if (
                credential_offer_entity.issuance_mode
                != CredentialIssuanceModes.Deferred.value
            ):
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} is not in deferred issuance mode"
                )

            if (
                credential_offer_entity.credential_status
                != CredentialStatuses.Pending.value
            ):
                raise UpdateCredentialOfferError(
                    f"Credential offer with id {credential_offer_id} is not in pending status"
                )

            credential_schema_entity: CredentialSchemaEntity = (
                credential_offer_entity.credential_schema
            )
            if data_attribute_values:
                data_attributes = json.loads(credential_schema_entity.data_attributes)
                self._validate_data_attribute_values_against_data_attributes(
                    data_attribute_values, data_attributes
                )

            credential_offer_entity = repo.update(
                credential_offer_id,
                data_attribute_values=json.dumps(data_attribute_values),
                credential_status=CredentialStatuses.Ready.value,
            )
            return credential_offer_entity.to_dict()

    async def update_credential_offer_from_authorisation_request(
        self, issuer_state: Optional[str] = None, **kwargs
    ) -> Union[CredentialOfferEntity, None]:
        assert self.credential_offer_repository, "Credential offer repository not found"

        if issuer_state:
            issuer_state_decoded = decode_header_and_claims_in_jwt(issuer_state)
            IssuerService.verify_issuer_state(issuer_state, self.key_did._key)

            credential_offer_id = issuer_state_decoded.claims.get("credential_offer_id")

            with self.credential_offer_repository as repo:
                credential_offer_entity = repo.get_by_id(credential_offer_id)
                if credential_offer_entity is None:
                    raise UpdateCredentialOfferError(
                        f"Credential offer with id {credential_offer_id} not found"
                    )

                if credential_offer_entity.is_pre_authorised:
                    raise CredentialOfferIsPreAuthorizedError(
                        f"Credential offer with id {credential_offer_id} is already pre-authorized"
                    )

                return repo.update(credential_offer_id, **kwargs)
        else:
            # Search the credential offer by client ID.
            client_id = kwargs.get("client_id")
            assert client_id, "Client ID not found"

            with self.credential_offer_repository as repo:
                credential_offer_entity = repo.get_by_client_id(client_id)
                if credential_offer_entity is None:
                    raise UpdateCredentialOfferError(
                        f"Credential offer with client ID {client_id} not found"
                    )
                credential_offer_entity = repo.update(
                    credential_offer_entity.id, **kwargs
                )
                return credential_offer_entity

    async def prepare_redirect_url_with_vp_token_request(
        self, credential_offer_id: str, client_metadata: dict, aud: str
    ) -> str:
        assert self.auth_domain, "Auth domain not found"
        assert self.credential_offer_repository, "Credential offer repository not found"

        iss_service = IssuerService(
            self.credential_issuer_configuration.credential_endpoint,
            logger=self.logger,
        )
        state = str(uuid.uuid4())
        iss = self.auth_domain
        exp = int(time.time()) + 3600
        response_type = "vp_token"
        response_mode = "direct_post"
        client_id = self.auth_domain
        redirect_uri = f"{self.auth_domain}/direct_post"
        scope = "openid"
        nonce = str(uuid.uuid4())
        key = self.key_did._key
        key_id = key.key_id
        definition_id = str(uuid.uuid4())
        input_descriptor_1_id = str(uuid.uuid4())
        input_descriptor_2_id = str(uuid.uuid4())
        input_descriptor_3_id = str(uuid.uuid4())
        presentation_definition = {
            "id": definition_id,
            "format": {"jwt_vc": {"alg": ["ES256"]}, "jwt_vp": {"alg": ["ES256"]}},
            "input_descriptors": [
                {
                    "id": input_descriptor_1_id,
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {"const": "VerifiableAttestation"},
                                },
                            }
                        ]
                    },
                },
                {
                    "id": input_descriptor_2_id,
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {"const": "VerifiableAttestation"},
                                },
                            }
                        ]
                    },
                },
                {
                    "id": input_descriptor_3_id,
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.type"],
                                "filter": {
                                    "type": "array",
                                    "contains": {"const": "VerifiableAttestation"},
                                },
                            }
                        ]
                    },
                },
            ],
        }
        vp_token_request = iss_service.create_vp_token_request(
            state=state,
            iss=iss,
            aud=aud,
            exp=exp,
            response_type=response_type,
            response_mode=response_mode,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            key_id=key_id,
            key=key,
            presentation_definition=presentation_definition,
        )
        # Save state to credential offer.
        with self.credential_offer_repository as repo:
            repo.update(
                id=credential_offer_id,
                vp_token_request_state=state,
                vp_token_request=vp_token_request,
            )
        encoded_params = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "response_type": response_type,
                "scope": scope,
                "redirect_uri": redirect_uri,
                "request": vp_token_request,
                "response_mode": response_mode,
                "state": state,
            }
        )
        redirection_base_url = client_metadata.get("authorization_endpoint")
        if redirection_base_url:
            redirection_url = f"{redirection_base_url}?{encoded_params}"
        else:
            redirection_url = f"openid:?{encoded_params}"

        return redirection_url

    async def prepare_redirect_url_with_id_token_request(
        self, credential_offer_id: str, client_metadata: dict
    ) -> str:
        assert self.auth_domain, "Auth domain not found"
        assert self.credential_offer_repository, "Credential offer repository not found"

        iss_service = IssuerService(
            self.credential_issuer_configuration.credential_endpoint,
            logger=self.logger,
        )
        state = str(uuid.uuid4())
        iss = self.auth_domain
        aud = self.key_did.did
        exp = int(time.time()) + 3600
        response_type = "id_token"
        response_mode = "direct_post"
        client_id = self.auth_domain
        redirect_uri = f"{self.auth_domain}/direct_post"
        scope = "openid"
        # nonce = auth_req.issuer_state
        nonce = str(uuid.uuid4())
        key = self.key_did._key
        key_id = key.key_id
        id_token_request = iss_service.create_id_token_request(
            state=state,
            iss=iss,
            aud=aud,
            exp=exp,
            response_type=response_type,
            response_mode=response_mode,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            key_id=key_id,
            key=key,
        )
        # Save state to credential offer.
        with self.credential_offer_repository as repo:
            repo.update(
                id=credential_offer_id,
                id_token_request_state=state,
                id_token_request=id_token_request,
            )
        encoded_params = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "response_type": response_type,
                "scope": scope,
                "redirect_uri": redirect_uri,
                "request": id_token_request,
                "request_uri": f"{self.issuer_domain}/request-uri/{credential_offer_id}",
                "response_mode": response_mode,
                "state": state,
            }
        )
        redirection_base_url = client_metadata.get("authorization_endpoint")
        if redirection_base_url:
            redirection_url = f"{redirection_base_url}?{encoded_params}"
        else:
            redirection_url = f"openid:?{encoded_params}"

        return redirection_url

    async def get_first_legal_entity(self) -> Union[LegalEntityEntity, None]:
        assert self.legal_entity_repository, "Legal entity repository not found"
        with self.legal_entity_repository as repo:
            return repo.get_first()

    async def create_credential_schema(
        self, credential_type: str, data_attributes: List[dict]
    ) -> dict:
        assert (
            self.credential_schema_repository
        ), "Credential schema repository not found"

        with self.credential_schema_repository as repo:
            credential_schema_entity = repo.create(
                legal_entity_id=self.legal_entity_entity.id,
                credential_type=credential_type,
                data_attributes=json.dumps(data_attributes),
            )
            return credential_schema_entity.to_dict()

    async def get_credential_schema_by_id(
        self, credential_schema_id: str
    ) -> CredentialSchemaEntity:
        assert (
            self.credential_schema_repository
        ), "Credential schema repository not found"
        with self.credential_schema_repository as repo:
            credential_schema_entity = repo.get_by_id(credential_schema_id)
            return credential_schema_entity

    async def get_all_credential_schema(self) -> List[CredentialSchemaEntity]:
        assert (
            self.credential_schema_repository
        ), "Credential schema repository not found"
        with self.credential_schema_repository as repo:
            return repo.get_all()

    async def delete_credential_schema_by_id(self, credential_schema_id) -> bool:
        assert (
            self.credential_schema_repository
        ), "Credential schema repository not found"
        with self.credential_schema_repository as repo:
            return repo.delete(credential_schema_id)

    def _validate_data_attribute_values_against_data_attributes(
        self, data_attribute_values: dict, data_attributes: List[dict]
    ):
        if len(data_attributes) != len(data_attribute_values):
            raise ValidateDataAttributeValuesAgainstDataAttributesError(
                f"Number of data attributes in schema ({len(data_attributes)}) does not match number of data attribute values ({len(data_attribute_values)})"
            )

        for data_attribute in data_attributes:
            if data_attribute.get("attribute_name") not in data_attribute_values.keys():
                raise ValidateDataAttributeValuesAgainstDataAttributesError(
                    f"Data attribute value for {data_attribute.get('attribute_name')} not found"
                )

    async def create_credential_offer(
        self,
        credential_schema_id: str,
        issuance_mode: str,
        is_pre_authorised: bool,
        supports_revocation: bool,
        user_pin: Optional[str] = None,
        client_id: Optional[str] = None,
        data_attribute_values: Optional[dict] = None,
    ) -> dict:
        assert self.credential_offer_repository, "Credential offer repository not found"
        assert (
            self.credential_schema_repository
        ), "Credential schema repository not found"

        if is_pre_authorised and not user_pin:
            raise UserPinRequiredError(
                "User pin is required for pre-authorised credential offers"
            )

        if is_pre_authorised and not client_id:
            raise ClientIdRequiredError(
                "Client id is required for pre-authorised credential offers"
            )

        if (
            issuance_mode == CredentialIssuanceModes.InTime
            and not data_attribute_values
        ):
            raise CreateCredentialOfferError(
                "Data attribute values are required for in time issuance"
            )

        with self.credential_schema_repository as repo:
            credential_schema_entity = repo.get_by_id(credential_schema_id)
            if not credential_schema_entity:
                raise CreateCredentialOfferError(
                    f"Credential schema with id {credential_schema_id} not found"
                )

        if data_attribute_values:
            data_attributes = json.loads(credential_schema_entity.data_attributes)
            self._validate_data_attribute_values_against_data_attributes(
                data_attribute_values, data_attributes
            )

        iat = int(time.time())
        exp = iat + 3600

        with self.credential_offer_repository as credential_offer_repo, self.credential_revocation_status_list_repository as revocation_repo:
            if supports_revocation:
                revocation_list = revocation_repo.reserve_revocation_index()
            credential_offer_entity = credential_offer_repo.create(
                credential_schema_id=credential_schema_entity.id,
                data_attribute_values=json.dumps(data_attribute_values)
                if data_attribute_values
                else None,
                issuance_mode=issuance_mode,
                is_pre_authorised=is_pre_authorised,
                user_pin=user_pin,
                client_id=client_id,
                credential_status=CredentialStatuses.Ready.value
                if data_attribute_values
                else CredentialStatuses.Pending.value,
                supports_revocation=supports_revocation,
                is_revoked=False,
                credential_revocation_status_list_index=revocation_list.last_assigned_index
                if supports_revocation
                else -1,
                credential_revocation_status_list_id=revocation_list.id
                if supports_revocation
                else None,
            )

            if is_pre_authorised:
                pre_authorised_code = IssuerService.create_pre_authorised_code(
                    iss=self.key_did.did,
                    aud=self.key_did.did,
                    sub=self.key_did.did,
                    iat=iat,
                    nbf=iat,
                    exp=exp,
                    kid=f"{self.key_did.did}#{self.key_did._method_specific_id}",
                    key=self.key_did._key,
                    credential_offer_id=credential_offer_entity.id,
                )

                credential_offer_entity = credential_offer_repo.update(
                    id=credential_offer_entity.id,
                    pre_authorised_code=pre_authorised_code,
                )
            else:
                issuer_state = IssuerService.create_issuer_state(
                    iss=self.key_did.did,
                    aud=self.key_did.did,
                    sub=self.key_did.did,
                    iat=iat,
                    nbf=iat,
                    exp=exp,
                    kid=f"{self.key_did.did}#{self.key_did._method_specific_id}",
                    key=self.key_did._key,
                    credential_offer_id=credential_offer_entity.id,
                )

                credential_offer_entity = credential_offer_repo.update(
                    id=credential_offer_entity.id, issuer_state=issuer_state
                )
        return credential_offer_entity.to_dict()

    async def delete_credential_offer(self, credential_offer_id: str) -> bool:
        assert self.credential_offer_repository, "Credential offer repository not found"
        with self.credential_offer_repository as repo:
            return repo.delete(credential_offer_id)

    async def get_credential_offer_by_id_and_credential_schema_id(
        self, credential_offer_id: str, credential_schema_id: str
    ) -> Union[CredentialOfferEntity, None]:
        assert self.credential_offer_repository, "Credential offer repository not found"
        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_id_and_credential_schema_id(
                id=credential_offer_id, credential_schema_id=credential_schema_id
            )
            return credential_offer_entity

    async def get_all_credential_offers_by_credential_schema_id(
        self, credential_schema_id: str
    ) -> List[CredentialOfferEntity]:
        assert self.credential_offer_repository, "Credential offer repository not found"
        with self.credential_offer_repository as repo:
            return repo.get_all_by_credential_schema_id(
                credential_schema_id=credential_schema_id
            )

    async def get_credential_offer_by_id(
        self, credential_offer_id: str
    ) -> Union[CredentialOfferEntity, None]:
        assert self.credential_offer_repository, "Credential offer repository not found"
        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            return credential_offer_entity

    async def _verify_vp_token(
        self, vp_token: str, redirect_uri: str, presentation_submission: str, state: str
    ) -> Tuple[str, bool]:
        presentation_submission = json.loads(presentation_submission)

        vp_token_decoded = decode_header_and_claims_in_jwt(vp_token)
        kid = vp_token_decoded.headers.get("kid")
        method_specific_identifier = kid.split("#")[1]
        key = self.key_did.method_specific_identifier_to_jwk(method_specific_identifier)

        IssuerService.verify_vp_token(vp_token, key)

        vc_in_vp = vp_token_decoded.claims.get("vp").get("verifiableCredential")[0]
        vc_in_vp_decoded = decode_header_and_claims_in_jwt(vc_in_vp)

        vc = vc_in_vp_decoded.claims.get("vc")

        valid_from = vc.get("validFrom")
        valid_from = datetime.strptime(valid_from, "%Y-%m-%dT%H:%M:%SZ")
        expiration_date = vc.get("expirationDate")
        expiration_date = datetime.strptime(expiration_date, "%Y-%m-%dT%H:%M:%SZ")

        current_datetime_utc = datetime.utcnow()

        if current_datetime_utc > expiration_date:
            error = "invalid_request"
            descriptor_id = presentation_submission.get("descriptor_map")[0].get("id")
            error_description = f"{descriptor_id} is expired"
            return (
                f"{redirect_uri}?error={error}&error_description={error_description}&state={state}",
                False,
            )

        if current_datetime_utc < valid_from:
            error = "invalid_request"
            descriptor_id = presentation_submission.get("descriptor_map")[0].get("id")
            error_description = f"{descriptor_id} is not yet valid"
            return (
                f"{redirect_uri}?error={error}&error_description={error_description}&state={state}",
                False,
            )

        if vc.get("credentialStatus"):
            # FIXME: Fetch status list and verify the credential status.
            error = "invalid_request"
            descriptor_id = presentation_submission.get("descriptor_map")[0].get("id")
            error_description = f"{descriptor_id} is revoked"
            return (
                f"{redirect_uri}?error={error}&error_description={error_description}&state={state}",
                False,
            )

        return "", True

    async def prepare_redirect_url_with_authorisation_code_and_state(
        self,
        id_token_response: Optional[str] = None,
        state: Optional[str] = None,
        vp_token_response: Optional[str] = None,
        presentation_submission: Optional[str] = None,
    ) -> str:
        assert self.credential_offer_repository, "Credential offer repository not found"

        # TODO: Validate id token response by generating JWK from client id.
        # if did:key identifier then obtain from method specific id, else obtain from /jwks endpoint

        # Query credential offer by id_token request state
        with self.credential_offer_repository as repo:
            if id_token_response:
                credential_offer_entity = repo.get_by_id_token_request_state(state)
                if credential_offer_entity is None:
                    raise InvalidStateInIDTokenResponseError(
                        f"Invalid state {state} in ID token response"
                    )
            elif vp_token_response:
                credential_offer_entity = repo.get_by_vp_token_request_state(state)
                if credential_offer_entity is None:
                    raise InvalidStateInIDTokenResponseError(
                        f"Invalid state {state} in VP token response"
                    )

                redirect_url, is_verified = await self._verify_vp_token(
                    vp_token_response,
                    credential_offer_entity.redirect_uri,
                    presentation_submission,
                    credential_offer_entity.authorisation_request_state,
                )
                if not is_verified:
                    # Redirects back with error and error_description in query params.
                    return redirect_url

            if credential_offer_entity.is_pre_authorised:
                raise CredentialOfferIsPreAuthorizedError(
                    f"Credential offer with id {credential_offer_entity.id} is already pre-authorized"
                )

            # Create authorisation code and new state and save to db.
            authorisation_code = str(uuid.uuid4())
            authorisation_code_state = str(uuid.uuid4())
            credential_offer_entity = repo.update(
                id=credential_offer_entity.id,
                authorisation_code=authorisation_code,
                authorisation_code_state=authorisation_code_state,
            )

            redirect_url = f"{credential_offer_entity.redirect_uri}?code={authorisation_code}&state={credential_offer_entity.authorisation_request_state}"
            return redirect_url

    async def create_access_token(
        self,
        grant_type: Optional[str] = None,
        code: Optional[str] = None,
        client_id: Optional[str] = None,
        code_verifier: Optional[str] = None,
        user_pin: Optional[str] = None,
        pre_authorised_code: Optional[str] = None,
        client_assertion: Optional[str] = None,
        client_assertion_type: Optional[str] = None,
    ) -> dict:
        assert grant_type in [
            authorisation_grant.value.grant_type
            for authorisation_grant in AuthorisationGrants
        ], "Invalid grant type"

        # Query credential offer by authorisation code
        with self.credential_offer_repository as repo:
            if grant_type == AuthorisationGrants.PreAuthorisedCode.value.grant_type:
                assert user_pin, "User pin not found"
                assert pre_authorised_code, "Pre-authorised code not found"

                IssuerService.verify_pre_authorised_code(
                    token=pre_authorised_code, key=self.key_did._key
                )

                pre_authorised_code_decoded = decode_header_and_claims_in_jwt(
                    pre_authorised_code
                )
                credential_offer_id = pre_authorised_code_decoded.claims.get(
                    "credential_offer_id"
                )
                credential_offer_entity = repo.get_by_id(credential_offer_id)
                if credential_offer_entity is None:
                    raise InvalidPreAuthorisedCodeError(
                        f"Invalid pre-authorised code {pre_authorised_code}"
                    )

                if credential_offer_entity.user_pin != user_pin:
                    raise InvalidUserPinError(f"Invalid user pin {user_pin}")
            else:
                assert code, "Code not found"
                assert client_id, "Client id not found"

                credential_offer_entity = repo.get_by_authorisation_code(code)
                if credential_offer_entity is None:
                    raise InvalidAuthorisationCodeError(
                        f"Invalid authorisation code {code}"
                    )

                if credential_offer_entity.client_id != client_id:
                    raise InvalidClientError(f"Invalid client {client_id}")

                if code_verifier:
                    code_challenge_to_be_verified = generate_code_challenge(
                        code_verifier
                    )
                    if (
                        code_challenge_to_be_verified
                        != credential_offer_entity.code_challenge
                    ):
                        raise InvalidCodeVerifierError(
                            f"Invalid code verifier {code_verifier}"
                        )

                if client_assertion:
                    # TODO: Verify client assertion
                    self.logger.debug(
                        f"Client assertion of type {client_assertion_type} is present."
                    )

            iat = int(time.time())
            exp = iat + 86400
            nonce = str(uuid.uuid4())

            access_token = AuthnService.create_access_token(
                iss=self.key_did.did,
                aud=self.key_did.did,
                sub=client_id,
                iat=iat,
                nbf=iat,
                exp=exp,
                nonce=nonce,
                kid=self.key_did._key.key_id,
                key=self.key_did._key,
                credential_offer_id=credential_offer_entity.id,
            )

            token_response = TokenResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=exp,
                c_nonce=nonce,
                c_nonce_expires_in=exp,
            )
            return token_response.to_dict()

    async def get_credential_offer_by_reference_using_credential_offer_uri(
        self,
        credential_offer_id: str,
    ) -> dict:
        # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.3

        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            credential_schema_entity: CredentialSchemaEntity = (
                credential_offer_entity.credential_schema
            )
            if credential_offer_entity is None:
                raise CredentialOfferNotFoundError(
                    f"Credential offer with id {credential_offer_id} not found"
                )
            credential_offer_by_reference = {
                "credential_issuer": self.issuer_domain,
                "credentials": [
                    {
                        "format": "jwt_vc",
                        "types": [
                            "VerifiableCredential",
                            "VerifiableAttestation",
                            credential_schema_entity.credential_type,
                        ],
                        "trust_framework": {
                            "name": "ebsi",
                            "type": "Accreditation",
                            "uri": "TIR link towards accreditation",
                        },
                    }
                ],
            }

            if credential_offer_entity.is_pre_authorised:
                credential_offer_by_reference["grants"] = {
                    AuthorisationGrants.PreAuthorisedCode.value.grant_type: {
                        AuthorisationGrants.PreAuthorisedCode.value.grant_data: credential_offer_entity.pre_authorised_code
                    },
                    "user_pin_required": True,
                }
            else:
                credential_offer_by_reference["grants"] = {
                    AuthorisationGrants.PreAuthorisedCode.value.grant_type: {
                        AuthorisationGrants.PreAuthorisedCode.value.grant_data: credential_offer_entity.issuer_state
                    }
                }
            return credential_offer_by_reference

    async def initiate_credential_offer(
        self,
        credential_offer_id: str,
    ) -> str:
        # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.3

        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            if credential_offer_entity is None:
                raise CredentialOfferNotFoundError(
                    f"Credential offer with id {credential_offer_id} not found"
                )
            openid_credential_offer_uri = f"openid-credential-offer://?credential_offer_uri={self.issuer_domain}/credential-offer/{credential_offer_id}"
            return openid_credential_offer_uri

    async def get_id_token_request_from_credential_offer(
        self,
        credential_offer_id: str,
    ) -> str:
        with self.credential_offer_repository as repo:
            credential_offer_entity = repo.get_by_id(credential_offer_id)
            if credential_offer_entity is None:
                raise CredentialOfferNotFoundError(
                    f"Credential offer with id {credential_offer_id} not found"
                )
            return credential_offer_entity.id_token_request
