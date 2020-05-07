import sys

import pytest
import pytest_twisted
from twisted.internet import defer, reactor

import consul
import consul.twisted


def sleep(seconds):
    """
    An asynchronous sleep function using twsited. Source:
    http://twistedmatrix.com/pipermail/twisted-python/2009-October/020788.html

    :type seconds: float
    """
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, seconds)
    return d


class TestConsul(object):

    @pytest_twisted.inlineCallbacks
    @pytest.mark.skipif(sys.version_info < (3, 6, 0),
                        reason="Python <3.6.1 twisted have a bug! ")
    def test_acl(self, acl_consul):
        yield sleep(0.8)

        c = consul.twisted.Consul(
            port=acl_consul.port, token=acl_consul.token)

        rules = """
            key "" {
                policy = "read"
            }
            key "private/" {
                policy = "deny"
            }
        """
        token = yield c.acl.create(rules=rules)

        raised = False
        try:
            yield c.acl.list(token=token)
        except consul.ACLPermissionDenied:
            raised = True
        assert raised

        destroyed = yield c.acl.destroy(token)
        assert destroyed is True

        query_service = 'foo'
        query_name = 'fooquery'
        query = yield c.query.create(query_service,
                                     query_name, token=acl_consul.token)

        # assert response contains query ID
        assert 'ID' in query \
               and query['ID'] is not None \
               and str(query['ID']) != ''
