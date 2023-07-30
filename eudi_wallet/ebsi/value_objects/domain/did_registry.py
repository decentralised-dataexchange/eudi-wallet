import typing
from dataclasses import dataclass, field

from dataclasses_json import DataClassJsonMixin, config


@dataclass
class InsertDIDDocumentParams(DataClassJsonMixin):
    did: str
    baseDocument: str
    vMethodId: str
    publicKey: str
    isSecp256k1: bool
    notBefore: int
    notAfter: int
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class InsertDIDDocumentLedgerResult(DataClassJsonMixin):
    _from: str = field(metadata=config(field_name="from"))
    to: str | None = None
    data: str | None = None
    value: str | None = None
    nonce: str | None = None
    chainId: str | None = None
    gasLimit: str | None = None
    gasPrice: str | None = None


@dataclass
class InsertDIDDocumentJSONRPC20ResponseBody(DataClassJsonMixin):
    result: InsertDIDDocumentLedgerResult | None = None
    jsonrpc: str = "2.0"
    id: str | None = None


@dataclass
class InsertDIDDocumentJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[InsertDIDDocumentParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "insertDidDocument"


@dataclass
class JSONRPCErrorBody(DataClassJsonMixin):
    code: int
    message: str


@dataclass
class JSONRPC20ErrorResponse(DataClassJsonMixin):
    jsonrpc: str
    error: JSONRPCErrorBody
    id: str


@dataclass
class AddVerificationMethodParams(DataClassJsonMixin):
    did: str
    vMethodId: str
    isSecp256k1: bool
    publicKey: str
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class AddVerificationMethodJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[AddVerificationMethodParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "addVerificationMethod"


@dataclass
class AddVerificationRelationshipParams(DataClassJsonMixin):
    did: str
    name: str
    vMethodId: str
    notBefore: int
    notAfter: int
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class AddVerificationRelationshipJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[AddVerificationRelationshipParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "addVerificationRelationship"


@dataclass
class AddVerificationRelationshipResult(DataClassJsonMixin):
    to: str = None
    data: str = None
    value: str = None
    nonce: str = None
    chainId: str = None
    gasLimit: str = None
    gasPrice: str = None
    _from: str = field(metadata=config(field_name="from"), default=None)


@dataclass
class AddVerificationRelationshipJSONRPC20ResponseBody(DataClassJsonMixin):
    jsonrpc: str = None
    id: str = None
    result: AddVerificationRelationshipResult = None


@dataclass
class AddVerificationMethodResult(DataClassJsonMixin):
    _from: str = field(metadata=config(field_name="from"))
    to: str
    data: str
    value: str
    nonce: str
    chainId: str
    gasLimit: str
    gasPrice: str


@dataclass
class AddVerificationMethodJSONRPC20ResponseBody(DataClassJsonMixin):
    jsonrpc: str = None
    id: str = None
    result: AddVerificationMethodResult = None
