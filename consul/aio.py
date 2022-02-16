from __future__ import absolute_import

import asyncio
import sys
import warnings

import aiohttp
from aiohttp import ClientTimeout

from consul import base

__all__ = ['Consul']
PY_341 = sys.version_info >= (3, 4, 1)


class HTTPClient(base.HTTPClient):
    """Asyncio adapter for python consul using aiohttp library"""

    def __init__(self, *args, loop=None, **kwargs):
        super(HTTPClient, self).__init__(*args, **kwargs)
        self._session = None
        self._loop = loop or asyncio.get_event_loop()

    async def _request(self, callback, method, uri, data=None, headers=None, total_timeout=None):
        connector = aiohttp.TCPConnector(loop=self._loop,
                                         verify_ssl=self.verify)
        async with aiohttp.ClientSession(connector=connector, timeout=ClientTimeout(total=total_timeout)) as session:
            self._session = session
            resp = await session.request(method=method,
                                         url=uri,
                                         data=data,
                                         headers=headers)
            body = await resp.text(encoding='utf-8')
            content = await resp.read()
            if resp.status == 599:
                raise base.Timeout
            r = base.Response(resp.status, resp.headers, body, content)
            await session.close()
            return callback(r)

    # python prior 3.4.1 does not play nice with __del__ method
    if PY_341:  # pragma: no branch
        def __del__(self):
            warnings.warn("Unclosed connector in aio.Consul.HTTPClient",
                          ResourceWarning)
            if self._session and not self._session.closed:
                warnings.warn("Unclosed connector in aio.Consul.HTTPClient",
                              ResourceWarning)
                asyncio.ensure_future(self.close())

    async def get(self, callback, path, params=None, headers=None, total_timeout=None):
        uri = self.uri(path, params)
        return await self._request(callback, 'GET', uri, headers=headers, total_timeout=total_timeout)

    async def put(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        return await self._request(callback,
                                   'PUT',
                                   uri,
                                   data=data,
                                   headers=headers)

    async def delete(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        return await self._request(callback,
                                   'DELETE',
                                   uri,
                                   data=data,
                                   headers=headers)

    async def post(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        return await self._request(callback,
                                   'POST',
                                   uri,
                                   data=data,
                                   headers=headers)

    async def close(self):
        await self._session.close()


class Consul(base.Consul):

    def __init__(self, *args, loop=None, **kwargs):
        self._loop = loop or asyncio.get_event_loop()
        super().__init__(*args, **kwargs)

    def http_connect(self, host, port, scheme, verify=True, cert=None):
        return HTTPClient(host, port, scheme, loop=self._loop,
                          verify=verify, cert=None)
