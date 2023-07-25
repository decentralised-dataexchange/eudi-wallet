import typing
from dataclasses import dataclass, field
from dataclasses_json import config
from dataclasses_json import DataClassJsonMixin


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
class SendSignedTransactionParams(DataClassJsonMixin):
    protocol: str
    unsignedTransaction: str
    r: str
    s: str
    v: str
    signedRawTransaction: str


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
class SendSignedTransactionJSONRPC20ResponseBody(DataClassJsonMixin):
    result: str | None = None
    jsonrpc: str = "2.0"
    id: str | None = None


@dataclass
class SendSignedTransactionJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[SendSignedTransactionParams] | None = None
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
class ToBeSignedTransaction(DataClassJsonMixin):
    to: str
    data: str
    value: str
    nonce: int
    chainId: int
    gas: int
    gasPrice: int
