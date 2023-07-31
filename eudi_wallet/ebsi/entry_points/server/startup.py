from eudi_wallet.ebsi.services.domain.utils.discovery import \
    discover_credential_issuer_and_authn_server


async def app_startup(app):
    (
        credential_issuer_configuration,
        auth_server_configuration,
    ) = await discover_credential_issuer_and_authn_server()

    app["credential_issuer_configuration"] = credential_issuer_configuration
    app["auth_server_configuration"] = auth_server_configuration
