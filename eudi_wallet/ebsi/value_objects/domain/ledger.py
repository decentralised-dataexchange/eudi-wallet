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
    params: typing.List[SendSignedTransactionParams] | None = None
    id: str | None = None
    jsonrpc: str = "2.0"
    method: str = "insertDidDocument"


@dataclass
class SendSignedTransactionJSONRPC20ResponseBody(DataClassJsonMixin):
    result: str | None = None
    jsonrpc: str = "2.0"
    id: str | None = None


@dataclass
class GetTransactionReceiptJSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[str] | None = None
    id: str | None = None
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
    blockHash: str = None
    blockNumber: str = None
    contractAddress: typing.Optional[str] = None
    cumulativeGasUsed: str = None
    from_: str = None
    gasUsed: str = None
    effectiveGasPrice: str = None
    logs: typing.List[TransactionReceiptLog] = None
    logsBloom: str = None
    status: str = None
    to: str = None
    transactionHash: str = None
    transactionIndex: str = None
    type: str = None


@dataclass
class TransactionReceiptJSONRPC20ResponseBody(DataClassJsonMixin):
    jsonrpc: str = None
    id: str = None
    result: TransactionReceiptResult = None
