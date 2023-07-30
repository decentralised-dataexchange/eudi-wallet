import asyncio
import typing

import aiohttp


class HttpClient:
    def __init__(self):
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()
        self.session = None

    async def get(
        self, url: str, headers=None, allow_redirects: bool = False
    ) -> aiohttp.ClientResponse:
        if self.session is None:
            raise RuntimeError("Session is closed")
        return await self.session.get(
            url, headers=headers, allow_redirects=allow_redirects
        )

    async def post(
        self, url: str, data=None, headers=None, allow_redirects: bool = False
    ) -> aiohttp.ClientResponse:
        if self.session is None:
            raise RuntimeError("Session is closed")
        return await self.session.post(
            url, data=data, headers=headers, allow_redirects=allow_redirects
        )

    async def call_every_n_seconds(
        self,
        method: str,
        url: str,
        condition: typing.Callable[[aiohttp.ClientResponse], bool],
        data: typing.Optional[typing.Dict] = None,
        headers: typing.Optional[typing.Dict] = None,
        n: int = 5,
    ) -> aiohttp.ClientResponse:
        while True:
            if method.lower() == "get":
                response = await self.get(url, headers=headers)
            elif method.lower() == "post":
                response = await self.post(url, data=data, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")

            if await condition(response):
                return response

            await asyncio.sleep(n)
