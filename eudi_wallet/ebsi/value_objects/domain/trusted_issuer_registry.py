import typing
from dataclasses import dataclass, field

from dataclasses_json import DataClassJsonMixin, config


@dataclass
class InsertIssuerParams(DataClassJsonMixin):
    did: str
    attributeData: str
    issuerType: int
    taoDid: str
    taoAttributeId: str
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class InsertIssuerJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[InsertIssuerParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "insertIssuer"


@dataclass
class SetAttributeDataParams(DataClassJsonMixin):
    did: str
    attributeData: str
    attributeId: str
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class SetAttributeDataJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[SetAttributeDataParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "setAttributeData"


@dataclass
class AddIssuerProxyParams(DataClassJsonMixin):
    did: str
    proxyData: str
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class AddIssuerProxyJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[AddIssuerProxyParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "addIssuerProxy"


@dataclass
class Result(DataClassJsonMixin):
    to: str
    data: str
    value: str
    nonce: str
    chainId: str
    gasLimit: str
    gasPrice: str
    from_: str = field(metadata=config(field_name="from"))


@dataclass
class JSONRPC20ResponseBody(DataClassJsonMixin):
    jsonrpc: str
    id: str
    result: Result


@dataclass
class ProxyData(DataClassJsonMixin):
    prefix: str
    headers: dict
    testSuffix: str
