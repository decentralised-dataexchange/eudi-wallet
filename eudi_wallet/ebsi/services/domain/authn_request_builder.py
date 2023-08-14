import time
import typing
import uuid
from dataclasses import dataclass

from dataclasses_json import DataClassJsonMixin


class AuthorizationRequestBuilder:
    @dataclass
    class AuthorizationDetails(DataClassJsonMixin):
        locations: list
        types: list
        type: str = "openid_credential"
        format: str = "jwt_vc"

    @dataclass
    class ClientMetadata(DataClassJsonMixin):
        jwks_uri: str
        authorization_endpoint: typing.Optional[str]

    @dataclass
    class AuthorizationRequestJwtPayload(DataClassJsonMixin):
        iss: str
        aud: str
        response_type: str
        scope: str
        nonce: str
        client_id: str
        redirect_uri: str
        client_metadata: "AuthorizationRequestBuilder.ClientMetadata"
        authorization_details: typing.List[
            "AuthorizationRequestBuilder.AuthorizationDetails"
        ]

    def __init__(
        self,
        *,
        iss: typing.Optional[str] = None,
        aud: typing.Optional[str] = None,
        response_type: typing.Optional[str] = None,
        scope: typing.Optional[str] = None,
        nonce: typing.Optional[str] = None,
        client_id: typing.Optional[str] = None,
        redirect_uri: typing.Optional[str] = None,
        client_metadata: typing.Optional[
            typing.List["AuthorizationRequestBuilder.ClientMetadata"]
        ] = None,
        authorization_details: typing.Optional[
            "AuthorizationRequestBuilder.AuthorizationDetail"
        ] = None,
    ):
        self.iss = iss
        self.aud = aud
        self.iat = int(time.time())
        self.exp = self.iat + 3600
        self.response_type = response_type
        self.scope = scope
        self.nonce = nonce or str(uuid.uuid4())
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_metadata = client_metadata
        self.authorization_details = authorization_details

    def _get_kid(self, key_did):
        return key_did.public_key_jwk.get("kid")

    def _get_endpoint_url(self, endpoint_url):
        return self.issuer_domain + endpoint_url

    def set_authorization_details(
        self,
        locations: typing.List[str],
        types: typing.List[str],
        type: str = "openid_credential",
        format: str = "jwt_vc",
    ):
        self.authorization_details = [
            AuthorizationRequestBuilder.AuthorizationDetails(
                locations=locations,
                types=types,
                type=type,
                format=format,
            )
        ]

    def set_client_metadata(
        self,
        jwks_uri: str,
        authorization_endpoint: typing.Optional[str] = "openid://",
    ):
        self.client_metadata = AuthorizationRequestBuilder.ClientMetadata(
            jwks_uri=jwks_uri,
            authorization_endpoint=authorization_endpoint,
        )

    def set_iat(self, iat: int):
        self.iat = iat
        self.exp = iat + 3600

    def build_authorization_request(
        self,
    ):
        return AuthorizationRequestBuilder.AuthorizationRequestJwtPayload(
            iss=self.iss,
            aud=self.aud,
            response_type=self.response_type,
            scope=self.scope,
            nonce=self.nonce,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            client_metadata=self.client_metadata,
            authorization_details=self.authorization_details,
        )
