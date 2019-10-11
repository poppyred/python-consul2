import operator
import re

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

        acls = c.acl.legacy_tokens.list(token=master_token)
        assert set([x['ID'] for x in acls]) == {master_token}

        assert c.acl.info('1' * 36) is None
        compare = [c.acl.info(master_token)]
        compare.sort(key=operator.itemgetter('ID'))
        assert acls == compare

        assert c.acl.legacy_tokens.info('1' * 36) is None
        compare = [c.acl.legacy_tokens.info(master_token)]
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

        token = c.acl.legacy_tokens.create(rules=rules, token=master_token)
        assert c.acl.legacy_tokens.info(token)['Rules'] == rules

        token2 = c.acl.clone(token, token=master_token)
        assert c.acl.info(token2)['Rules'] == rules

        token2 = c.acl.legacy_tokens.clone(token, token=master_token)
        assert c.acl.legacy_tokens.info(token2)['Rules'] == rules

        assert c.acl.update(token2, name='Foo', token=master_token,
                            type='client', rules=rules) == token2

        assert c.acl.legacy_tokens.update(token2,
                                          name='Foo',
                                          token=master_token,
                                          type='client',
                                          rules=rules) == token2

        assert c.acl.info(token2)['Name'] == 'Foo'

        assert c.acl.destroy(token2, token=master_token) is True
        assert c.acl.legacy_tokens.destroy(token2, token=master_token) is True
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
        [c.acl.destroy(x['ID'],
                       token=master_token) for x in acls
         if x['ID'] != master_token]
        assert master_token in set([x['ID'] for x in acls])

    def test_acl_implicit_token_use(self, acl_consul):
        # configure client to use the master token by default
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        master_token = acl_consul.token

        acls = c.acl.list()
        assert master_token in set([x['ID'] for x in acls])

        assert c.acl.info('foo') is None
        compare = [c.acl.info(master_token)]
        compare.sort(key=operator.itemgetter('ID'))
        assert acls == compare

        assert c.acl.self()['Description'] == 'Master Token'

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

        assert c.agent.service.maintenance('foo', 'true', "test") is True

        # clean up
        c.acl.destroy(token)
        c.acl.destroy(token2)
        acls = c.acl.list()
        assert set([x['ID'] for x in acls]) == {master_token}

    def test_acl_bootstrap(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)

        index = None
        try:
            c.acl.bootstrap()
        except Exception as e:
            index = re.search(r".*:(.*)\)", str(e)).group(1)
        with open('acl-bootstrap-reset', 'w') as f:
            f.write(str(index))
        bootstrap = c.acl.bootstrap()
        assert bootstrap['Policies'][0] == {
            'ID': '00000000-0000-0000-0000-000000000001',
            'Name': 'global-management'}

    def test_acl_replication(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        # todo cluster replication test
        assert not c.acl.replication()['Enabled']

    def test_acl_translate(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)

        payload = """
        agent "" {
            policy = "write"
        }
        """

        translate = c.acl.create_translate(
            payload=payload, token=acl_consul.token)
        assert translate == b'agent_prefix "" {\n  policy = "write"\n}'

        # fixme
        pytest.raises(consul.ConsulException,
                      c.acl.get_translate,
                      c.acl.self()['AccessorID'],
                      acl_consul.token)

    @pytest.mark.skip(reason='The auth_method has not been used')
    def test_acl_login(self, acl_consul):
        # c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        # fixme c.acl.login()
        pass

    @pytest.mark.skip(reason='The auth_method has not been used')
    def test_acl_logout(self, acl_consul):
        # c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        # fixme c.acl.logout()
        pass

    def test_acl_tokens(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)

        policy = c.acl.policy.create(name='node-read',
                                     rules='node_prefix \"\" '
                                           '{ policy = \"read\"}',
                                     description='Grants read access '
                                                 'to all node information',
                                     datacenters=["dc1"])
        payload = {
            "Description": "Agent token for 'node1'",
            "Policies": [
                {
                    "ID": policy["ID"]
                },
                {
                    "Name": policy["Name"]
                }
            ],
            "Local": False
        }

        token_list1 = c.acl.tokens.list()
        assert 'Master Token' in [l['Description'] for l in token_list1]
        token1 = c.acl.tokens.create(payload)
        assert token1['Description'] == payload['Description']
        token2 = c.acl.tokens.update(accessor_id=token1['AccessorID'],
                                     payload=payload)
        assert token2['AccessorID'] == token1['AccessorID']
        token3 = c.acl.tokens.get(accessor_id=token2['AccessorID'])
        assert token3['AccessorID'] == token1['AccessorID']
        token_self = c.acl.tokens.self()
        assert token_self['Description'] == 'Master Token'
        token4 = c.acl.tokens.clone(accessor_id=token3['AccessorID'],
                                    description='i am clone')
        assert token4['AccessorID'] != token3['AccessorID']
        assert c.acl.tokens.delete(accessor_id=token4['AccessorID'])
        token_list2 = c.acl.tokens.list()
        assert len(token_list2) == len(token_list1) + 1

    def test_acl_policy(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)

        policy = c.acl.policy.create(name='node-read',
                                     rules='node_prefix \"\" '
                                           '{ policy = \"read\"}',
                                     description='Grants read access '
                                                 'to all node information',
                                     datacenters=["dc1"])

        policy_list = c.acl.policy.list()
        assert policy['ID'] in [p['ID'] for p in policy_list]
        policy = c.acl.policy.update(policy['ID'],
                                     name='node-read1',
                                     rules='node_prefix \"\" '
                                           '{ policy = \"read\"}',
                                     description='Grants read access '
                                                 'to all node information',
                                     datacenters=["dc1"])
        assert policy['Name'] == 'node-read1'
        policy2 = c.acl.policy.get(policy['ID'])
        assert policy2['ID'] == policy['ID']

        assert c.acl.policy.delete(policy['ID'])
        policy_list = c.acl.policy.list()
        assert policy['ID'] not in [p['ID'] for p in policy_list]

    def test_acl_roles(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        policy = c.acl.policy.create(name='node-read',
                                     rules='node_prefix \"\" '
                                           '{ policy = \"read\"}',
                                     description='Grants read access '
                                                 'to all node information',
                                     datacenters=["dc1"])
        payload = {
            "Name": "example-role",
            "Description": "Showcases all input parameters",
            "Policies": [
                {
                    "ID": policy['ID']
                },
                {
                    "Name": "node-read"
                }
            ],
            "ServiceIdentities": [
                {
                    "ServiceName": "web"
                },
                {
                    "ServiceName": "db",
                    "Datacenters": [
                        "dc1"
                    ]
                }
            ]
        }
        role = c.acl.roles.create(payload=payload)
        assert role['Name'] == 'example-role'
        payload['Name'] = 'example-role1'
        role = c.acl.roles.update(role_id=role['ID'], payload=payload)
        assert role['Name'] == 'example-role1'
        role = c.acl.roles.get(role['ID'])
        assert role['Name'] == 'example-role1'
        assert 'example-role1' in [r['Name'] for r in c.acl.roles.list()]
        assert c.acl.roles.delete(role['ID'])
        assert 'example-role1' not in [r['Name'] for r in c.acl.roles.list()]

    def test_acl_roles(self, acl_consul):
        c = consul.Consul(port=acl_consul.port, token=acl_consul.token)
        policy = c.acl.policy.create(name='node-read',
                                     rules='node_prefix \"\" '
                                           '{ policy = \"read\"}',
                                     description='Grants read access '
                                                 'to all node information',
                                     datacenters=["dc1"])
        payload = {
            "Name": "example-role",
            "Description": "Showcases all input parameters",
            "Policies": [
                {
                    "ID": policy['ID']
                },
                {
                    "Name": "node-read"
                }
            ],
            "ServiceIdentities": [
                {
                    "ServiceName": "web"
                },
                {
                    "ServiceName": "db",
                    "Datacenters": [
                        "dc1"
                    ]
                }
            ]
        }
        role = c.acl.roles.create(payload=payload)
        assert role['Name'] == 'example-role'
        payload['Name'] = 'example-role1'
        role = c.acl.roles.update(role_id=role['ID'], payload=payload)
        assert role['Name'] == 'example-role1'
        role = c.acl.roles.get(role['ID'])
        assert role['Name'] == 'example-role1'
        assert 'example-role1' in [r['Name'] for r in c.acl.roles.list()]
        assert c.acl.roles.delete(role['ID'])
        assert 'example-role1' not in [r['Name'] for r in c.acl.roles.list()]

