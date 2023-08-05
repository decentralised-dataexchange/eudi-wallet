import typing
from dataclasses import dataclass

from dataclasses_json import DataClassJsonMixin


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
class SendSignedTransactionParams(DataClassJsonMixin):
    protocol: str
    unsignedTransaction: str
    r: str
    s: str
    v: str
    signedRawTransaction: str


@dataclass
class SendSignedTransactionJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.Optional[typing.List[SendSignedTransactionParams]] = None
    id: typing.Optional[str] = None
    jsonrpc: str = "2.0"
    method: str = "insertDidDocument"


@dataclass
class SendSignedTransactionJSONRPC20ResponseBody(DataClassJsonMixin):
    result: typing.Optional[str] = None
    jsonrpc: str = "2.0"
    id: typing.Optional[str] = None


@dataclass
class GetTransactionReceiptJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.Optional[typing.List[str]] = None
    id: typing.Optional[str] = None
    jsonrpc: str = "2.0"
    method: str = "eth_getTransactionReceipt"


@dataclass
class TransactionReceiptLog(DataClassJsonMixin):
    address: str = None
    topics: typing.List[str] = None
    data: str = None
    blockNumber: str = None
    transactionHash: str = None
    transactionIndex: str = None
    blockHash: str = None
    logIndex: str = None
    removed: bool = None


@dataclass
class TransactionReceiptResult(DataClassJsonMixin):
    blockHash: typing.Optional[str] = None
    blockNumber: typing.Optional[str] = None
    contractAddress: typing.Optional[str] = None
    cumulativeGasUsed: typing.Optional[str] = None
    from_: typing.Optional[str] = None
    gasUsed: typing.Optional[str] = None
    effectiveGasPrice: typing.Optional[str] = None
    logs: typing.Optional[typing.List[TransactionReceiptLog]] = None
    logsBloom: typing.Optional[str] = None
    status: typing.Optional[str] = None
    to: typing.Optional[str] = None
    transactionHash: typing.Optional[str] = None
    transactionIndex: typing.Optional[str] = None
    type: typing.Optional[str] = None


@dataclass
class TransactionReceiptJSONRPC20ResponseBody(DataClassJsonMixin):
    jsonrpc: str = None
    id: str = None
    result: TransactionReceiptResult = None
