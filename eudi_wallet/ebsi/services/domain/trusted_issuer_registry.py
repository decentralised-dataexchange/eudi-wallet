import logging
from typing import Optional

from eudi_wallet.ebsi.exceptions.domain.trusted_issuer_registry import (
    AddIssuerProxyError,
    SetAttributeDataError,
)
from eudi_wallet.ebsi.utils.http_client import HttpClient
from eudi_wallet.ebsi.value_objects.domain.trusted_issuer_registry import (
    AddIssuerProxyJSONRPC20RequestBody,
    InsertIssuerJSONRPC20RequestBody,
    JSONRPC20ResponseBody,
    SetAttributeDataJSONRPC20RequestBody,
)


class TIRService:
    def __init__(
        self,
        trusted_issuer_registry_rpc_endpoint: Optional[str] = None,
        access_token: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.trusted_issuer_registry_rpc_endpoint = trusted_issuer_registry_rpc_endpoint
        self.access_token = access_token
        self.logger = logger

    def set_access_token(self, access_token: str) -> None:
        self.access_token = access_token

    async def insert_issuer(
        self,
        payload: InsertIssuerJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while setting attribute data: {await response.text()}"
            )
            raise SetAttributeDataError(
                f"Error occured while setting attribute data. Response status: {response.status}"
            )

    async def set_attribute_data(
        self,
        payload: SetAttributeDataJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while setting attribute data: {await response.text()}"
            )
            raise SetAttributeDataError(
                f"Error occured while setting attribute data. Response status: {response.status}"
            )

    async def add_issuer_proxy(
        self,
        payload: AddIssuerProxyJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while setting attribute data: {await response.text()}"
            )
            raise AddIssuerProxyError(
                f"Error occured while setting attribute data. Response status: {response.status}"
            )
