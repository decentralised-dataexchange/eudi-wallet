import logging
from typing import Optional

from eudi_wallet.ebsi.exceptions.domain.did_registry import (
    AddVerificationMethodError,
    AddVerificationRelationshipError,
    InsertDIDDocumentError,
)
from eudi_wallet.ebsi.utils.http_client import HttpClient
from eudi_wallet.ebsi.value_objects.domain.did_registry import (
    AddVerificationMethodJSONRPC20RequestBody,
    AddVerificationMethodJSONRPC20ResponseBody,
    AddVerificationRelationshipJSONRPC20RequestBody,
    AddVerificationRelationshipJSONRPC20ResponseBody,
    InsertDIDDocumentJSONRPC20RequestBody,
    InsertDIDDocumentJSONRPC20ResponseBody,
)


class DIDRegistryService:
    def __init__(
        self,
        did_registry_rpc_endpoint: Optional[str] = None,
        besu_rpc_endpoint: Optional[str] = None,
        access_token: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.did_registry_rpc_endpoint = did_registry_rpc_endpoint
        self.besu_rpc_endpoint = besu_rpc_endpoint
        self.access_token = access_token
        self.logger = logger

    def set_access_token(self, access_token: str) -> None:
        self.access_token = access_token

    async def insert_did_document(
        self,
        payload: InsertDIDDocumentJSONRPC20RequestBody,
    ) -> InsertDIDDocumentJSONRPC20ResponseBody:
        assert self.did_registry_rpc_endpoint, "DID registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.did_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            return InsertDIDDocumentJSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            raise InsertDIDDocumentError(
                f"Error occured while inserting DID document. Response status: {response.status}"
            )

    async def add_verification_method(
        self,
        payload: AddVerificationMethodJSONRPC20RequestBody,
    ) -> AddVerificationMethodJSONRPC20ResponseBody:
        assert self.did_registry_rpc_endpoint, "DID registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.did_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            return AddVerificationMethodJSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            raise AddVerificationMethodError(
                f"Error occured while updating verification method in DID document. Response status: {response.status}"
            )

    async def add_verification_relationship(
        self,
        payload: AddVerificationRelationshipJSONRPC20RequestBody,
    ) -> AddVerificationRelationshipJSONRPC20ResponseBody:
        assert self.did_registry_rpc_endpoint, "DID registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.did_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            return AddVerificationRelationshipJSONRPC20ResponseBody.from_dict(
                rpc_result
            )
        else:
            raise AddVerificationRelationshipError(
                f"Error occured while updating verification method in DID document. Response status: {response.status}"
            )
