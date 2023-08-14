import asyncio

from jsonschema.validators import Draft202012Validator

from eudi_wallet.ebsi.utils.httpx_client import HttpxClient


class PresentationDefinitionService:
    def __init__(self, schema_url: str) -> None:
        self.schema_url = schema_url

    async def load_from_remote_registry(self):
        async with HttpxClient() as http_client:
            response = await http_client.get(self.schema_url)

        if response.status_code != 200:
            raise Exception("Failed to fetch schema from remote registry")

        schema = response.json()
        validator = Draft202012Validator.check_schema()


if __name__ == "__main__":

    async def main():
        presentation_definition_service = PresentationDefinitionService(
            schema_url="https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/zGUR7RxCZtwQFSdwow63xF8hP2gMtH55incKsADwrcwzZ"
        )
        await presentation_definition_service.load_from_remote_registry()

    asyncio.run(main())
