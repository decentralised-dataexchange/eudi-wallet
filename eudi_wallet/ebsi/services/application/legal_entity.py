import json
import time
import typing
import uuid
from logging import Logger

from eth_account import Account
from eth_account.signers.local import LocalAccount
from jwcrypto import jwk

from eudi_wallet.ebsi.entities.application.legal_entity import \
    LegalEntityEntity
from eudi_wallet.ebsi.exceptions.application.legal_entity import \
    StatusListNotFoundError
from eudi_wallet.ebsi.repositories.application.legal_entity import \
    SqlAlchemyLegalRepository
from eudi_wallet.ebsi.services.domain.authn import AuthnService
from eudi_wallet.ebsi.services.domain.authn_request_builder import \
    AuthorizationRequestBuilder
from eudi_wallet.ebsi.services.domain.did_registry import DIDRegistryService
from eudi_wallet.ebsi.services.domain.issuer import IssuerService
from eudi_wallet.ebsi.services.domain.ledger import LedgerService
from eudi_wallet.ebsi.services.domain.trusted_issuer_registry import TIRService
from eudi_wallet.ebsi.services.domain.utils.credential import (
    CredentialStatus, create_credential_token, deserialize_credential_jwt,
    generate_w3c_vc_statuslist_encoded_bitstring)
from eudi_wallet.ebsi.services.domain.utils.did import generate_and_store_did
from eudi_wallet.ebsi.utils.date_time import generate_ISO8601_UTC
from eudi_wallet.ebsi.utils.hex import convert_string_to_hex
from eudi_wallet.ebsi.utils.jwt import decode_header_and_claims_in_jwt
from eudi_wallet.ebsi.value_objects.domain.authn import (
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
    CredentialProof, CredentialRequest, CredentialRequestPayload,
    CredentialResponse, CredentialTypes, SendCredentialRequest,
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
        credential_issuer_configuration: OpenIDCredentialIssuerConfig,
        auth_server_configuration: OpenIDAuthServerConfig,
        logger: Logger,
        issuer_domain: str,
        repository: SqlAlchemyLegalRepository,
    ):
        self.key_did = None
        self.ebsi_did = None
        self.eth = None
        self.legal_entity_entity = None
        self.credential_issuer_configuration = credential_issuer_configuration
        self.auth_server_configuration = auth_server_configuration
        self.logger = logger
        self.issuer_domain = issuer_domain
        self.repository = repository

    async def set_cryptographic_seed(self, crypto_seed: str) -> None:
        self.crypto_seed = crypto_seed
        self.eth, self.ebsi_did, self.key_did = await generate_and_store_did(
            crypto_seed
        )

    async def set_entity(self, legal_entity_entity: LegalEntityEntity) -> None:
        self.legal_entity_entity = legal_entity_entity

    async def get_access_token_for_ebsi_services(
        self,
        ebsi_auth_client: AuthnService,
        verifiableCredential: typing.List[str],
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
        credential_types: typing.List[str],
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

    async def fill_did_registry(self) -> CredentialResponse:
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

        return credential

    async def fill_trusted_issuer_registry(self) -> CredentialResponse:
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

        return credential

    async def onboard_trusted_issuer(self):
        assert self.legal_entity_entity, "Legal entity not found"

        try:
            vc_to_onboard = await self.fill_did_registry()
            vc_to_attest = await self.fill_trusted_issuer_registry()

            self.repository.update(
                id=self.legal_entity_entity.id,
                is_onboarding_in_progress=False,
                is_onboarded=True,
                verifiable_authorisation_to_onboard=vc_to_onboard.credential,
                verifiable_accreditation_to_attest=vc_to_attest.credential,
            )
        except Exception as e:
            self.logger.debug(f"Error onboarding trusted issuer: {e}")
            self.repository.update(
                id=self.legal_entity_entity.id,
                is_onboarding_in_progress=False,
                is_onboarded=False,
                cryptographic_seed=f"{int(time.time())}",
            )

    async def issue_credential(self, credential_request_dict: dict) -> dict:
        assert self.legal_entity_entity, "Legal entity not found"

        vc_to_attest: VerifiableAccreditationToAttest = deserialize_credential_jwt(
            self.legal_entity_entity.verifiable_accreditation_to_attest
        )
        reserved_attribute_id = (
            vc_to_attest.credentialSubject.reservedAttributeId.lstrip("0x")
        )
        schema = vc_to_attest.credentialSubject.accreditedFor[0].schemaId
        proxy_id = "0x3891c95836d83d81627bf946b84a63eb027a039f0753c98343b5b59bc6fd3c2e"
        credential_status_suffix = "/credentials/status/1"
        credential_status_url = f"https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/issuers/{self.ebsi_did.did}/proxies/{proxy_id}{credential_status_suffix}"

        credential_request = CredentialRequest.from_dict(credential_request_dict)

        credential_type = credential_request.types[-1]
        self.logger.debug(f"Processing credential request for: {credential_type}")

        decoded_token = decode_header_and_claims_in_jwt(credential_request.proof.jwt)
        credential_subject = decoded_token.headers["kid"].split("#")[0]

        if credential_type == CredentialTypes.CTRevocable.value:
            jti = f"urn:uuid:{str(uuid.uuid4())}"

            seconds_in_one_year = 31536000
            iss_in_epoch, issuance_date = generate_ISO8601_UTC()
            exp_in_epoch, expiration_date = generate_ISO8601_UTC(seconds_in_one_year)
            ct_revocable_vc = {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "id": jti,
                "type": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "CTRevocable",
                ],
                "issuer": self.ebsi_did.did,
                "issuanceDate": issuance_date,
                "validFrom": issuance_date,
                "expirationDate": expiration_date,
                "issued": issuance_date,
                "credentialSubject": {"id": credential_subject},
                "credentialStatus": {
                    "id": f"{credential_status_url}#list",
                    "type": "StatusList2021Entry",
                    "statusPurpose": "revocation",
                    "statusListIndex": "0",
                    "statusListCredential": credential_status_url,
                },
                "termsOfUse": [
                    {
                        "id": f"https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/issuers/{self.ebsi_did.did}/attributes/{reserved_attribute_id}",
                        "type": "IssuanceCertificate",
                    }
                ],
                "credentialSchema": {
                    "id": schema,
                    "type": "FullJsonSchemaValidator2021",
                },
            }
            key = self.key_did._key
            to_be_issued_credential = create_credential_token(
                vc=ct_revocable_vc,
                jti=jti,
                sub=credential_subject,
                iss=self.ebsi_did.did,
                kid=f"{self.ebsi_did.did}#{key.key_id}",
                key=key,
                iat=iss_in_epoch,
                exp=exp_in_epoch,
            )

        credential_response = CredentialResponse(
            format="jwt_vc", credential=to_be_issued_credential
        )

        self.logger.debug(
            f"Issued CTRevocable credential: {credential_response.to_json(indent=4)}"
        )
        return credential_response.to_dict()

    async def get_credential_status(self, status_list_index: int) -> dict:
        assert self.legal_entity_entity, "Legal entity not found"
        if status_list_index != 1:
            raise StatusListNotFoundError(
                f"Status list with index {status_list_index} not found."
            )

        vc_to_attest: VerifiableAccreditationToAttest = deserialize_credential_jwt(
            self.legal_entity_entity.verifiable_accreditation_to_attest
        )
        reserved_attribute_id = (
            vc_to_attest.credentialSubject.reservedAttributeId.lstrip("0x")
        )
        schema = vc_to_attest.credentialSubject.accreditedFor[0].schemaId

        status_list_encoded_bitstring = generate_w3c_vc_statuslist_encoded_bitstring(
            credential_statuses=[
                CredentialStatus(status_list_index=status_list_index, is_revoked=False)
            ]
        )

        credential_list_url = f"{self.issuer_domain}/credentials/status/1#list"

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
                "encodedList": status_list_encoded_bitstring,
            },
            "credentialSchema": [
                {
                    "id": schema,
                    "type": "FullJsonSchemaValidator2021",
                }
            ],
            "termsOfUse": {
                "id": f"https://api-conformance.ebsi.eu/trusted-issuers-registry/v4/issuers/{self.ebsi_did.did}/attributes/{reserved_attribute_id}",
                "type": "IssuanceCertificate",
            },
        }

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
