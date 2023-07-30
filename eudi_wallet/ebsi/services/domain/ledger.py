import logging

from aiohttp.web_response import Response
from eth_account.datastructures import SignedTransaction
from web3.auto import w3

from eudi_wallet.ebsi.exceptions.domain.ledger import \
    SendSignedTransactionError
from eudi_wallet.ebsi.utils.http_client import HttpClient
from eudi_wallet.ebsi.value_objects.domain.ledger import (
    GetTransactionReceiptJSONRPC20RequestBody,
    SendSignedTransactionJSONRPC20RequestBody,
    SendSignedTransactionJSONRPC20ResponseBody, ToBeSignedTransaction,
    TransactionReceiptJSONRPC20ResponseBody)


class LedgerService:
    def __init__(
        self,
        registry_rpc_endpoint: str | None = None,
        besu_rpc_endpoint: str | None = None,
        access_token: str | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.registry_rpc_endpoint = registry_rpc_endpoint
        self.besu_rpc_endpoint = besu_rpc_endpoint
        self.access_token = access_token
        self.logger = logger

    def set_access_token(self, access_token: str) -> None:
        self.access_token = access_token

    def set_registry_rpc_endpoint(self, registry_rpc_endpoint: str) -> None:
        self.registry_rpc_endpoint = registry_rpc_endpoint

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

        async with HttpClient() as http_client:
            response = await http_client.post(
                self.registry_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_response_dict = await response.json()
            return SendSignedTransactionJSONRPC20ResponseBody.from_dict(
                rpc_response_dict
            )
        else:
            raise SendSignedTransactionError(
                f"Error occured while sending signed transaction. Response status: {response.status}"
            )

    async def get_transaction_receipt(
        self,
        payload: GetTransactionReceiptJSONRPC20RequestBody,
    ) -> TransactionReceiptJSONRPC20ResponseBody:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }

        async def check_transaction_result(res: Response):
            transaction_result = await res.json()
            receipt = transaction_result.get("result")

            if receipt:
                status = int(receipt["status"], 16)

                if status == 1:
                    return True
                else:
                    revert_reason = bytes.fromhex(
                        receipt["revertReason"].lstrip("0x")
                    ).decode("utf-8")
                    raise Exception(
                        f"Transaction failed: Status {receipt['status']}. Revert reason: {revert_reason}"
                    )

        async with HttpClient() as http_client:
            await http_client.call_every_n_seconds(
                "post",
                self.besu_rpc_endpoint,
                check_transaction_result,
                payload.to_json(),
                headers,
                5,
            )
            response = await http_client.post(
                self.besu_rpc_endpoint, payload.to_json(), headers
            )
        if response.status == 200:
            rpc_response = await response.json()
            return TransactionReceiptJSONRPC20ResponseBody.from_dict(rpc_response)
        else:
            raise SendSignedTransactionError(
                f"Error occured while sending signed transaction. Response status: {response.status}"
            )
