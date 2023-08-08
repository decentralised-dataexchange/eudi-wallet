import logging
from typing import Optional

from eudi_wallet.ebsi.exceptions.domain.trusted_issuer_registry import (
    AddAttributeMetadataError,
    AddIssuerProxyError,
    ListIssuerAttributesError,
    ListIssuerProxiesError,
    SetAttributeDataError,
)
from eudi_wallet.ebsi.utils.httpx_client import HttpxClient
from eudi_wallet.ebsi.value_objects.domain.trusted_issuer_registry import (
    AddIssuerProxyJSONRPC20RequestBody,
    InsertIssuerJSONRPC20RequestBody,
    JSONRPC20ResponseBody,
    ListIssuerAttributesResponse,
    ListProxiesResponse,
    SetAttributeDataJSONRPC20RequestBody,
    SetAttributeMetadataJSONRPC20RequestBody,
)


class TIRService:
    def __init__(
        self,
        trusted_issuer_registry_rpc_endpoint: Optional[str] = None,
        trusted_issuer_registry_api_endpoint: Optional[str] = None,
        access_token: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.trusted_issuer_registry_rpc_endpoint = trusted_issuer_registry_rpc_endpoint
        self.trusted_issuer_registry_api_endpoint = trusted_issuer_registry_api_endpoint
        self.access_token = access_token
        self.logger = logger

    def set_access_token(self, access_token: str) -> None:
        self.access_token = access_token

    async def insert_issuer(
        self,
        payload: InsertIssuerJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint is not None
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token is not None, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status_code == 200:
            rpc_result = response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while setting attribute data: {response.text}"
            )
            raise SetAttributeDataError(
                f"Error occured while setting attribute data. Response status: {response.status}"
            )

    async def set_attribute_data(
        self,
        payload: SetAttributeDataJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint is not None
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token is not None, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status_code == 200:
            rpc_result = response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while setting attribute data: {response.text}"
            )
            raise SetAttributeDataError(
                f"Error occured while setting attribute data. Response status: {response.status}"
            )

    async def add_issuer_proxy(
        self,
        payload: AddIssuerProxyJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint is not None
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token is not None, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status_code == 200:
            rpc_result = response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while setting attribute data: {response.text}"
            )
            raise AddIssuerProxyError(
                f"Error occured while setting attribute data. Response status: {response.status}"
            )

    async def get_all_issuer_proxies_for_did(self, did: str) -> ListProxiesResponse:
        assert (
            self.trusted_issuer_registry_api_endpoint is not None
        ), "Trusted issuer registry API endpoint is not set"

        list_proxies_endpoint = (
            f"{self.trusted_issuer_registry_api_endpoint}/issuers/{did}/proxies"
        )
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.get(list_proxies_endpoint)
        if response.status_code == 200:
            proxies = response.json()
            return ListProxiesResponse.from_dict(proxies)
        else:
            self.logger.debug(
                f"Error occured while listing issuer proxies: {response.text}"
            )
            raise ListIssuerProxiesError(
                f"Error occured while listing issuer proxies. Response status: {response.status}"
            )

    async def get_all_attributes_for_did(
        self, did: str
    ) -> ListIssuerAttributesResponse:
        assert (
            self.trusted_issuer_registry_api_endpoint is not None
        ), "Trusted issuer registry API endpoint is not set"

        list_proxies_endpoint = (
            f"{self.trusted_issuer_registry_api_endpoint}/issuers/{did}/attributes"
        )
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.get(list_proxies_endpoint)
        if response.status_code == 200:
            proxies = response.json()
            return ListIssuerAttributesResponse.from_dict(proxies)
        else:
            self.logger.debug(
                f"Error occured while listing attributes: {response.text}"
            )
            raise ListIssuerAttributesError(
                f"Error occured while listing attributes. Response status: {response.status}"
            )

    async def add_attribute_metadata(
        self,
        payload: SetAttributeMetadataJSONRPC20RequestBody,
    ) -> JSONRPC20ResponseBody:
        assert (
            self.trusted_issuer_registry_rpc_endpoint is not None
        ), "Trusted issuer registry RPC endpoint is not set"
        assert self.access_token is not None, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpxClient(logger=self.logger) as http_client:
            response = await http_client.post(
                self.trusted_issuer_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status_code == 200:
            rpc_result = response.json()
            return JSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            self.logger.debug(
                f"Error occured while while adding attribute metadata: {response.text}"
            )
            raise AddAttributeMetadataError(
                f"Error occured while adding attribute metadata. Response status: {response.status}"
            )
