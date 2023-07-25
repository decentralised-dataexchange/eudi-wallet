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
