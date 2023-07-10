import logging, aiohttp, typing
from dataclasses import dataclass, field
from dataclasses_json import config
from dataclasses_json import DataClassJsonMixin

logger = logging.getLogger(__name__)


class InsertDIDDocumentError(Exception):
    pass


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
class LedgerResult(DataClassJsonMixin):
    _from: str = field(metadata=config(field_name="from"))
    to: str = None
    data: str = None
    value: str = None
    nonce: str = None
    chainId: str = None
    gasLimit: str = None
    gasPrice: str = None


@dataclass
class JSONRPC20ResponseBody(DataClassJsonMixin):
    result: LedgerResult
    jsonrpc: str = "2.0"
    id: str = None


@dataclass
class JSONRPC20RequestBody(DataClassJsonMixin):
    params: InsertDIDDocumentParams = None
    id: str = None
    jsonrpc: str = "2.0"
    method: str = "insertDidDocument"


@dataclass
class MakeInsertDIDDocumentRPCCall(DataClassJsonMixin):
    payload: typing.List[JSONRPC20RequestBody]
    rpc_uri: str
    access_token: str

@dataclass
class JSONRPCErrorBody(DataClassJsonMixin):
    code: int
    message: str

@dataclass
class JSONRPC20ErrorResponse(DataClassJsonMixin):
    jsonrpc: str
    error: JSONRPCErrorBody
    id: str


async def make_insert_did_document_rpc_call(
    payload: MakeInsertDIDDocumentRPCCall,
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
                raise InsertDIDDocumentError(
                    f"Error occured while inserting DID document. Response status: {response.status}"
                )
