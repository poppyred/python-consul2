import pytest_twisted

import consul
import consul.twisted


class TestConsul(object):

    @pytest_twisted.inlineCallbacks
    def test_acl(self, acl_consul):
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
