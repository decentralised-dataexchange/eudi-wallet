from typing import Optional

from eudi_wallet.ebsi.utils.http_client import HttpClient
from eudi_wallet.ebsi.value_objects.domain.discovery import (
    OpenIDAuthServerConfig,
    OpenIDCredentialIssuerConfig,
)


class DiscoveryService:
    def __init__(
        self,
        issuer_config_endpoint: Optional[str] = None,
        authn_config_endpoint: Optional[str] = None,
    ) -> None:
        self.issuer_config_endpoint = issuer_config_endpoint
        self.authn_config_endpoint = authn_config_endpoint

    async def fetch_credential_issuer_config(self) -> OpenIDCredentialIssuerConfig:
        assert self.issuer_config_endpoint, "Issuer config endpoint is not set"
        async with HttpClient() as http_client:
            response = await http_client.get(self.issuer_config_endpoint)

        if response.status == 200:
            issuer_config_dict = await response.json()
            issuer_config = OpenIDCredentialIssuerConfig(**issuer_config_dict)
            self.authn_config_endpoint = (
                f"{issuer_config.authorization_server}/.well-known/openid-configuration"
            )
            return issuer_config
        else:
            raise Exception("Invalid response status")

    async def fetch_authorization_server_config(self) -> OpenIDAuthServerConfig:
        assert self.authn_config_endpoint, "Authn config endpoint is not set"
        async with HttpClient() as http_client:
            response = await http_client.get(self.authn_config_endpoint)

        if response.status == 200:
            authn_config = await response.json()
            return OpenIDAuthServerConfig(**authn_config)
        else:
            raise Exception("Invalid response status")
