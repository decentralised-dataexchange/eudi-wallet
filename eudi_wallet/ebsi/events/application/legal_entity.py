from dataclasses import dataclass

from dataclasses_json import DataClassJsonMixin


@dataclass
class OnboardTrustedIssuerEvent(DataClassJsonMixin):
    issuer_domain: str
    crypto_seed: str
    openid_credential_issuer_config: dict
    auth_server_config: dict
