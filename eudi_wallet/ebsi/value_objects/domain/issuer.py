import typing
from dataclasses import dataclass, field
from enum import Enum

from dataclasses_json import DataClassJsonMixin, config


class IssuerTrustFrameworks(Enum):
    EBSI = "EBSI"


class EBSICredentialTypes(Enum):
    VerifiableAuthorisationToOnboard = "VerifiableAuthorisationToOnboard"
    VerifiableAccreditationToAttest = "VerifiableAccreditationToAttest"
    VerifiableAccreditationToAccredit = "VerifiableAccreditationToAccredit"
    CTAAQualificationCredential = "CTAAQualificationCredential"
    CTWalletQualificationCredential = "CTWalletQualificationCredential"
    CTRevocable = "CTRevocable"


class CredentialTypes(Enum):
    VerifiableCredential = "VerifiableCredential"
    VerifiableAttestation = "VerifiableAttestation"
    VerifiableAuthorisationToOnboard = "VerifiableAuthorisationToOnboard"
    VerifiableAccreditation = "VerifiableAccreditation"
    VerifiableAccreditationToAttest = "VerifiableAccreditationToAttest"
    VerifiableAccreditationToAccredit = "VerifiableAccreditationToAccredit"
    VerifiableAuthorisationForTrustChain = "VerifiableAuthorisationForTrustChain"
    CTAAQualificationCredential = "CTAAQualificationCredential"
    CTWalletQualificationCredential = "CTWalletQualificationCredential"
    CTRevocable = "CTRevocable"


class CredentialIssuanceModes(Enum):
    InTime = "InTime"
    Deferred = "Deferred"


class CredentialStatuses(Enum):
    Ready = "ready"
    Pending = "pending"


class CredentialOfferStatuses(Enum):
    OfferSent = "offer_send"
    OfferReceived = "offer_received"
    CredentialIssued = "credential_issued"
    CredentialAcknowledged = "credential_ack"


@dataclass
class AcceptanceTokenResponse(DataClassJsonMixin):
    acceptance_token: typing.Optional[str] = None
    c_nonce: typing.Optional[str] = None
    c_nonce_expires_in: typing.Optional[int] = None


@dataclass
class CredentialResponse(DataClassJsonMixin):
    acceptance_token: typing.Optional[str] = None
    format: typing.Optional[str] = None
    credential: typing.Optional[str] = None
    c_nonce: typing.Optional[str] = None
    c_nonce_expires_in: typing.Optional[int] = None


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


@dataclass
class VAOCredentialSubject(DataClassJsonMixin):
    _id: str = field(metadata=config(field_name="id"))


@dataclass
class CredentialSchema(DataClassJsonMixin):
    _type: str = field(metadata=config(field_name="type"))
    _id: str = field(metadata=config(field_name="id"))


@dataclass
class TermsOfUse(DataClassJsonMixin):
    _id: str = field(metadata=config(field_name="id"))
    _type: str = field(metadata=config(field_name="type"))


@dataclass
class VerifiableAuthorisationToOnboard(DataClassJsonMixin):
    issuer: str
    issuanceDate: str
    issued: str
    validFrom: str
    expirationDate: str
    credentialSubject: VAOCredentialSubject
    credentialSchema: CredentialSchema
    termsOfUse: TermsOfUse
    context: typing.List[str] = field(metadata=config(field_name="@context"))
    _type: typing.List[str] = field(metadata=config(field_name="type"))
    _id: str = field(metadata=config(field_name="id"))


@dataclass
class AccreditedFor(DataClassJsonMixin):
    schemaId: str
    types: typing.List[str]
    limitJurisdiction: str


@dataclass
class VACredentialSubject(DataClassJsonMixin):
    accreditedFor: typing.List[AccreditedFor]
    reservedAttributeId: str
    _id: str = field(metadata=config(field_name="id"))


@dataclass
class VerifiableAccreditation(DataClassJsonMixin):
    issuer: str
    issuanceDate: str
    issued: str
    validFrom: str
    expirationDate: str
    credentialSubject: VACredentialSubject
    credentialSchema: CredentialSchema
    termsOfUse: TermsOfUse
    _id: str = field(metadata=config(field_name="id"))
    _type: typing.List[str] = field(metadata=config(field_name="type"))
    context: typing.List[str] = field(metadata=config(field_name="@context"))


@dataclass
class CredentialRequestProof(DataClassJsonMixin):
    proof_type: str
    jwt: str


@dataclass
class CredentialRequest(DataClassJsonMixin):
    format: str
    types: typing.List[str]
    proof: CredentialRequestProof


@dataclass
class VATCCredentialSubject(DataClassJsonMixin):
    reservedAttributeId: str
    _id: str = field(metadata=config(field_name="id"))


@dataclass
class VerifiableAuthorisationForTrustChain(DataClassJsonMixin):
    issuer: str
    issuanceDate: str
    issued: str
    validFrom: str
    expirationDate: str
    credentialSubject: VATCCredentialSubject
    credentialSchema: CredentialSchema
    termsOfUse: TermsOfUse
    context: typing.List[str] = field(metadata=config(field_name="@context"))
    _id: str = field(metadata=config(field_name="id"))
    _type: typing.List[str] = field(metadata=config(field_name="type"))
