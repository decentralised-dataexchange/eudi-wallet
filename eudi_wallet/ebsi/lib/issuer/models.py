import typing
from dataclasses import dataclass
from dataclasses_json import DataClassJsonMixin


@dataclass
class CredentialResponse(DataClassJsonMixin):
    format: typing.Optional[str | None] = None
    credential: typing.Optional[str | None] = None
    c_nonce: typing.Optional[str | None] = None
    c_nonce_expires_in: typing.Optional[str | None] = None


@dataclass
class CreateCredentialRequest(DataClassJsonMixin):
    kid: str
    iss: str
    aud: str
    nonce: str


@dataclass
class CredentialRequestJWTToken(DataClassJsonMixin):
    token: str


@dataclass
class CredentialProof(DataClassJsonMixin):
    jwt: str
    proof_type: str = "jwt"


@dataclass
class CredentialRequestPayload(DataClassJsonMixin):
    types: typing.List[str]
    proof: CredentialProof
    format: str = "jwt_vc"


@dataclass
class SendCredentialRequest(DataClassJsonMixin):
    credential_uri: str
    token: str
    payload: CredentialRequestPayload


@dataclass
class ToBeSignedTransaction(DataClassJsonMixin):
    to: str
    data: str
    value: str
    nonce: int
    chainId: int
    gas: int
    gasPrice: int
