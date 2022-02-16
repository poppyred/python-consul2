from __future__ import absolute_import

from tornado import gen
from tornado import httpclient

from consul import base

__all__ = ['Consul']


class HTTPClient(base.HTTPClient):
    def __init__(self, *args, **kwargs):
        super(HTTPClient, self).__init__(*args, **kwargs)
        self.client = httpclient.AsyncHTTPClient()

    @staticmethod
    def response(response):
        return base.Response(
            response.code,
            response.headers,
            response.body.decode('utf-8'),
            response.body)

    @gen.coroutine
    def _request(self, callback, request):
        try:
            response = yield self.client.fetch(request)
        except httpclient.HTTPError as e:
            if e.code == 599:
                raise base.Timeout
            response = e.response
        raise gen.Return(callback(self.response(response)))

    def get(self, callback, path, params=None, headers=None, total_timeout=None):
        uri = self.uri(path, params)
        request = httpclient.HTTPRequest(uri,
                                         method='GET',
                                         validate_cert=self.verify,
                                         headers=headers,
                                         connect_timeout=total_timeout)
        return self._request(callback, request)

    def put(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        request = httpclient.HTTPRequest(uri,
                                         method='PUT',
                                         body='' if data is None else data,
                                         validate_cert=self.verify,
                                         headers=headers)
        return self._request(callback, request)

    def delete(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        request = httpclient.HTTPRequest(uri,
                                         method='DELETE',
                                         body='' if data is None else data,
                                         validate_cert=self.verify,
                                         headers=headers)
        request.allow_nonstandard_methods = True
        return self._request(callback, request)

    def post(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        request = httpclient.HTTPRequest(uri,
                                         method='POST',
                                         body=data,
                                         validate_cert=self.verify,
                                         headers=headers)
        return self._request(callback, request)


class Consul(base.Consul):
    @staticmethod
    def http_connect(host, port, scheme, verify=True, cert=None):
        return HTTPClient(host, port, scheme, verify=verify, cert=cert)
