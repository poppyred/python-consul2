import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from consul import base

__all__ = ['Consul']


class HTTPClient(base.HTTPClient):
    def __init__(self, *args, **kwargs):
        """
        Connect using a default retry policy. This can be disabled by setting
        retries=None.
        """
        retries = kwargs.pop('retries', Retry(total=5, backoff_factor=0.2))
        super(HTTPClient, self).__init__(*args, **kwargs)
        self.session = requests.Session()
        if retries:
            self.session.mount('http://', HTTPAdapter(max_retries=retries))
            self.session.mount('https://', HTTPAdapter(max_retries=retries))

    @staticmethod
    def response(response):
        response.encoding = 'utf-8'
        return base.Response(
            response.status_code,
            response.headers,
            response.text,
            response.content)

    def get(self, callback, path, params=None, headers=None):
        uri = self.uri(path, params)
        return callback(self.response(
            self.session.get(uri,
                             headers=headers,
                             verify=self.verify,
                             cert=self.cert,
                             timeout=self.timeout)))

    def put(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        return callback(self.response(
            self.session.put(uri,
                             data=data,
                             headers=headers,
                             verify=self.verify,
                             cert=self.cert,
                             timeout=self.timeout)))

    def delete(self, callback, path, params=None, data='', headers=None):
        uri = self.uri(path, params)
        return callback(self.response(
            self.session.delete(uri,
                                data=data,
                                headers=headers,
                                verify=self.verify,
                                cert=self.cert,
                                timeout=self.timeout)))

    def post(self, callback, path, params=None, headers=None, data=''):
        uri = self.uri(path, params)
        return callback(self.response(
            self.session.post(uri,
                              data=data,
                              headers=headers,
                              verify=self.verify,
                              cert=self.cert,
                              timeout=self.timeout)))


class Consul(base.Consul):
    @staticmethod
    def http_connect(host, port, scheme, verify=True, cert=None, timeout=None, **kwargs):
        return HTTPClient(host, port, scheme, verify, cert, timeout, **kwargs)
