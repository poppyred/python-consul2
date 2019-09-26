import pytest
from tornado import gen
from tornado import ioloop

import consul
import consul.tornado


@pytest.fixture
def loop():
    loop = ioloop.IOLoop()
    loop.make_current()
    return loop



class TestConsulACL(object):
    def test_acl(self, loop, acl_consul):
        @gen.coroutine
        def main():
            c = consul.tornado.Consul(
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

            try:
                yield c.acl.list(token=token)
            except consul.ACLPermissionDenied:
                raised = True
            assert raised

            destroyed = yield c.acl.destroy(token)
            assert destroyed is True
            loop.stop()

        loop.run_sync(main)
