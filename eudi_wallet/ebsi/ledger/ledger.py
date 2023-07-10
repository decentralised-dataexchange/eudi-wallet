import typing
import aiohttp
import logging
from web3.auto import w3
from eth_account.datastructures import SignedTransaction
from dataclasses import dataclass
from dataclasses_json import DataClassJsonMixin


logger = logging.getLogger(__name__)


class SendSignedTransactionError(Exception):
    pass


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
class JSONRPC20RequestBody(DataClassJsonMixin):
    params: typing.List[SendSignedTransactionParams] = None
    id: str = None
    jsonrpc: str = "2.0"
    method: str = "sendSignedTransaction"


@dataclass
class MakeSendSignedTransactionRPCCall(DataClassJsonMixin):
    payload: JSONRPC20RequestBody
    rpc_uri: str
    access_token: str


@dataclass
class JSONRPC20ResponseBody(DataClassJsonMixin):
    result: str = None
    jsonrpc: str = "2.0"
    id: str = None


@dataclass
class JSONRPCErrorBody(DataClassJsonMixin):
    code: int
    message: str


@dataclass
class JSONRPC20ErrorResponse(DataClassJsonMixin):
    jsonrpc: str
    error: JSONRPCErrorBody
    id: str


async def sign_ledger_transaction(
    tbs: ToBeSignedTransaction, eth_private_key: bytes
) -> SignedTransaction:
    signed_transaction = w3.eth.account.sign_transaction(
        tbs.to_dict(), private_key=eth_private_key
    )
    return signed_transaction


async def make_send_signed_transaction_rpc_call(
    payload: MakeSendSignedTransactionRPCCall,
) -> JSONRPC20ResponseBody:
    url = f"{payload.rpc_uri}"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {payload.access_token}",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(
            url, data=payload.payload.to_json(), headers=headers
        ) as response:
            if response.status == 200:
                logger.info(f"Response status: {response.status}")
                rpc_response_dict = await response.json()
                return JSONRPC20ResponseBody.from_dict(rpc_response_dict)
            else:
                rpc_response_dict = await response.json()
                rpc_response = JSONRPC20ErrorResponse.from_dict(rpc_response_dict)
                logger.error(f"Response status: {response.status}")
                logger.error(f"Response error: {rpc_response.error.message}")
                logger.error(f"Response error code: {rpc_response.error.code}")
                raise SendSignedTransactionError(
                    f"Error occured while sending signed transaction. Response status: {response.status}"
                )
