import operator

import pytest
import six

import consul


class TestConsulACL(object):

    def test_acl_permission_denied(self, acl_consul):
        c = consul.Consul(port=acl_consul.port)
        pytest.raises(consul.ACLPermissionDenied, c.acl.list)
        pytest.raises(consul.ACLPermissionDenied, c.acl.create)
        pytest.raises(consul.ACLPermissionDenied, c.acl.update, 'anonymous')
        pytest.raises(consul.ACLPermissionDenied, c.acl.clone, 'anonymous')
        pytest.raises(consul.ACLPermissionDenied, c.acl.destroy, 'anonymous')

    def test_acl_explict_token_use(self, acl_consul):
        c = consul.Consul(port=acl_consul.port)
        master_token = acl_consul.token

        acls = c.acl.list(token=master_token)
        assert set([x['ID'] for x in acls]) == {master_token}

        assert c.acl.info('1' * 36) is None
        compare = [c.acl.info(master_token)]
        compare.sort(key=operator.itemgetter('ID'))
        assert acls == compare

        rules = """
            node "" {
                policy = "read"
            }
            key "" {
                policy = "read"
            }
            key "private/" {
                policy = "deny"
            }
            service "foo-" {
                policy = "write"
            }
            service "bar-" {
                policy = "read"
            }
        """

        token = c.acl.create(rules=rules, token=master_token)
        assert c.acl.info(token)['Rules'] == rules

        token2 = c.acl.clone(token, token=master_token)
        assert c.acl.info(token2)['Rules'] == rules

        assert c.acl.update(token2, name='Foo', token=master_token,
                            type='client', rules=rules) == token2
        assert c.acl.info(token2)['Name'] == 'Foo'

        assert c.acl.destroy(token2, token=master_token) is True
        assert c.acl.info(token2) is None

        c.kv.put('foo', 'bar', token=master_token)
        c.kv.put('private/foo', 'bar', token=master_token)

        assert c.kv.get('foo', token=token)[1]['Value'] == six.b('bar')
        pytest.raises(
            consul.ACLPermissionDenied, c.kv.put, 'foo', 'bar2', token=token)
        pytest.raises(
            consul.ACLPermissionDenied, c.kv.delete, 'foo', token=token)

        assert c.kv.get('private/foo',
                        token=master_token)[1]['Value'] == six.b('bar')
        pytest.raises(
            consul.ACLPermissionDenied,
            c.kv.get, 'private/foo', token=token)
        pytest.raises(
            consul.ACLPermissionDenied,
            c.kv.put, 'private/foo', 'bar2', token=token)
        pytest.raises(
            consul.ACLPermissionDenied,
            c.kv.delete, 'private/foo', token=token)

        # test token pass through for service registration
        pytest.raises(
            consul.ACLPermissionDenied,
            c.agent.service.register, "bar-1", token=token)
        c.agent.service.register("foo-1", token=token)
        index, data = c.health.service('foo-1', token=token)
        assert data[0]['Service']['ID'] == "foo-1"
        index, data = c.health.checks('foo-1', token=token)
        assert data == []
        index, data = c.health.service('bar-1', token=token)
        assert not data

        # clean up
        assert c.agent.service.deregister('foo-1', token=token) is True
        c.acl.destroy(token, token=master_token)
        acls = c.acl.list(token=master_token)
        assert set([x['ID'] for x in acls]) == {master_token}

    def test_acl_implicit_token_use(self, acl_consul):
        # configure client to use the master token by default
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        master_token = acl_consul.token

        acls = c.acl.list()
        assert set([x['ID'] for x in acls]) == {master_token}

        assert c.acl.info('foo') is None
        compare = [c.acl.info(master_token)]
        compare.sort(key=operator.itemgetter('ID'))
        assert acls == compare

        rules = """
            key "" {
                policy = "read"
            }
            key "private/" {
                policy = "deny"
            }
        """
        token = c.acl.create(rules=rules)
        assert c.acl.info(token)['Rules'] == rules

        token2 = c.acl.clone(token)
        assert c.acl.info(token2)['Rules'] == rules

        assert c.acl.update(token2, name='Foo') == token2
        assert c.acl.info(token2)['Name'] == 'Foo'

        assert c.acl.destroy(token2) is True
        assert c.acl.info(token2) is None

        c.kv.put('foo', 'bar')
        c.kv.put('private/foo', 'bar')

        c_limited = consul.Consul(port=acl_consul.port, token=token)
        assert c_limited.kv.get('foo')[1]['Value'] == six.b('bar')
        pytest.raises(
            consul.ACLPermissionDenied, c_limited.kv.put, 'foo', 'bar2')
        pytest.raises(
            consul.ACLPermissionDenied, c_limited.kv.delete, 'foo')

        assert c.kv.get('private/foo')[1]['Value'] == six.b('bar')
        pytest.raises(
            consul.ACLPermissionDenied,
            c_limited.kv.get, 'private/foo')
        pytest.raises(
            consul.ACLPermissionDenied,
            c_limited.kv.put, 'private/foo', 'bar2')
        pytest.raises(
            consul.ACLPermissionDenied,
            c_limited.kv.delete, 'private/foo')

        # check we can override the client's default token
        pytest.raises(
            consul.ACLPermissionDenied,
            c.kv.get, 'private/foo', token=token
        )
        pytest.raises(
            consul.ACLPermissionDenied,
            c.kv.put, 'private/foo', 'bar2', token=token)
        pytest.raises(
            consul.ACLPermissionDenied,
            c.kv.delete, 'private/foo', token=token)

        # clean up
        c.acl.destroy(token)
        acls = c.acl.list()
        assert set([x['ID'] for x in acls]) == {master_token}

        assert c.agent.service.maintenance('foo', 'true', "test") is True
