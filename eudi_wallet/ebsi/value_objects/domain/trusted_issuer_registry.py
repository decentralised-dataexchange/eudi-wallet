import typing
from dataclasses import dataclass, field

from dataclasses_json import DataClassJsonMixin, config


@dataclass
class InsertIssuerParams(DataClassJsonMixin):
    did: str
    issuerType: int
    taoDid: str
    taoAttributeId: str
    _from: str = field(metadata=config(field_name="from"))
    attributeData: typing.Optional[str] = None


@dataclass
class InsertIssuerJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.Optional[typing.List[InsertIssuerParams]] = None
    id: typing.Optional[str] = None
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
    params: typing.Optional[typing.List[SetAttributeDataParams]] = None
    id: typing.Optional[str] = None
    jsonrpc: str = "2.0"
    method: str = "setAttributeData"


@dataclass
class AddIssuerProxyParams(DataClassJsonMixin):
    did: str
    proxyData: str
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class AddIssuerProxyJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[AddIssuerProxyParams] = None
    id: typing.Optional[str] = None
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


@dataclass
class ProxyItem(DataClassJsonMixin):
    proxyId: str
    href: str


@dataclass
class ListProxiesResponse(DataClassJsonMixin):
    items: typing.List[ProxyItem]
    total: int


@dataclass
class AttributeItem(DataClassJsonMixin):
    id: str
    href: str


@dataclass
class Links(DataClassJsonMixin):
    first: str
    prev: str
    next: str
    last: str


@dataclass
class ListIssuerAttributesResponse(DataClassJsonMixin):
    self: str
    items: typing.List[AttributeItem]
    total: int
    pageSize: int
    links: Links


@dataclass
class SetAttributeMetadataParams(DataClassJsonMixin):
    did: str
    attributeId: str
    issuerType: int
    taoDid: str
    taoAttributeId: str
    _from: str = field(metadata=config(field_name="from"))


@dataclass
class SetAttributeMetadataJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[SetAttributeMetadataParams] = None
    id: typing.Optional[str] = None
    jsonrpc: str = "2.0"
    method: str = "setAttributeMetadata"
