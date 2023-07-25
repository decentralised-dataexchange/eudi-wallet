import logging
from web3.auto import w3
from eth_account.datastructures import SignedTransaction
from eudi_wallet.ebsi.lib.did_registry.models import (
    InsertDIDDocumentJSONRPC20ResponseBody,
    SendSignedTransactionJSONRPC20ResponseBody,
    InsertDIDDocumentJSONRPC20RequestBody,
    SendSignedTransactionJSONRPC20RequestBody,
    ToBeSignedTransaction,
)
from eudi_wallet.ebsi.lib.utils.http_client import HttpClient
from eudi_wallet.ebsi.lib.did_registry.exceptions import (
    InsertDIDDocumentError,
    SendSignedTransactionError,
)

logger = logging.getLogger(__name__)


class DIDRegistryClient:
    def __init__(
        self,
        did_registry_rpc_endpoint: str | None = None,
        access_token: str | None = None,
    ) -> None:
        self.did_registry_rpc_endpoint = did_registry_rpc_endpoint
        self.access_token = access_token

    def set_access_token(self, access_token: str) -> None:
        self.access_token = access_token

    async def insert_did_document(
        self,
        payload: InsertDIDDocumentJSONRPC20RequestBody,
    ) -> InsertDIDDocumentJSONRPC20ResponseBody:
        assert self.did_registry_rpc_endpoint, "DID registry RPC endpoint is not set"
        assert self.access_token, "Access token is not set"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.did_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_result = await response.json()
            logger.info(f"RPC result: {rpc_result}")
            return InsertDIDDocumentJSONRPC20ResponseBody.from_dict(rpc_result)
        else:
            raise InsertDIDDocumentError(
                f"Error occured while inserting DID document. Response status: {response.status}"
            )

    async def sign_ledger_transaction(
        self, tbs: ToBeSignedTransaction, eth_private_key: bytes
    ) -> SignedTransaction:
        signed_transaction = w3.eth.account.sign_transaction(
            tbs.to_dict(), private_key=eth_private_key
        )
        return signed_transaction

    async def send_signed_transaction(
        self,
        payload: SendSignedTransactionJSONRPC20RequestBody,
    ) -> SendSignedTransactionJSONRPC20ResponseBody:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        logger.info(f"Payload: {payload.to_json()}")
        async with HttpClient() as http_client:
            response = await http_client.post(
                self.did_registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_response_dict = await response.json()
            logger.info(f"RPC response: {rpc_response_dict}")
            return SendSignedTransactionJSONRPC20ResponseBody.from_dict(
                rpc_response_dict
            )
        else:
            raise SendSignedTransactionError(
                f"Error occured while sending signed transaction. Response status: {response.status}"
            )
