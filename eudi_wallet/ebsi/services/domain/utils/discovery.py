import typing
from logging import Logger

from eudi_wallet.ebsi.services.domain.discovery import DiscoveryService
from eudi_wallet.ebsi.value_objects.domain.discovery import (
    OpenIDAuthServerConfig,
    OpenIDCredentialIssuerConfig,
)


async def discover_credential_issuer_and_authn_server(
    logger: typing.Optional[Logger] = None,
) -> typing.Tuple[OpenIDCredentialIssuerConfig, OpenIDAuthServerConfig]:
    discovery_client = DiscoveryService(
        issuer_config_endpoint="https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/.well-known/openid-credential-issuer",
        logger=logger,
    )
    credential_issuer_configuration = (
        await discovery_client.fetch_credential_issuer_config()
    )
    auth_server_configuration = (
        await discovery_client.fetch_authorization_server_config()
    )

    return credential_issuer_configuration, auth_server_configuration
