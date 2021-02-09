import base64
import os
import struct
import time

import pytest
import six

import consul
import consul.std
from consul.base import Weight

Check = consul.Check


class TestHTTPClient(object):
    def test_uri(self):
        http = consul.std.HTTPClient()
        assert http.uri('/v1/kv') == 'http://127.0.0.1:8500/v1/kv'
        assert http.uri(
            '/v1/kv',
            params={'index': 1}) == 'http://127.0.0.1:8500/v1/kv?index=1'


class TestConsul(object):
    def test_kv(self, consul_port):
        c = consul.Consul(port=consul_port)
        index, data = c.kv.get('foo')
        assert data is None
        assert c.kv.put('foo', 'bar') is True
        index, data = c.kv.get('foo')
        assert data['Value'] == six.b('bar')

    def test_kv_wait(self, consul_port):
        c = consul.Consul(port=consul_port)
        assert c.kv.put('foo', 'bar') is True
        index, data = c.kv.get('foo')
        check, data = c.kv.get('foo', index=index, wait='20ms')
        assert index == check

    def test_kv_encoding(self, consul_port):
        c = consul.Consul(port=consul_port)

        # test binary
        c.kv.put('foo', struct.pack('i', 1000))
        index, data = c.kv.get('foo')
        assert struct.unpack('i', data['Value']) == (1000,)

        # test unicode
        c.kv.put('foo', u'bar')
        index, data = c.kv.get('foo')
        assert data['Value'] == six.b('bar')

        # test empty-string comes back as `None`
        c.kv.put('foo', '')
        index, data = c.kv.get('foo')
        assert data['Value'] is None

        # test None
        c.kv.put('foo', None)
        index, data = c.kv.get('foo')
        assert data['Value'] is None

        # check unencoded values raises assert * Python3 don't need
        # pytest.raises(AssertionError, c.kv.put, 'foo', {1: 2})

    def test_kv_put_cas(self, consul_port):
        c = consul.Consul(port=consul_port)
        assert c.kv.put('foo', 'bar', cas=50) is False
        assert c.kv.put('foo', 'bar', cas=0) is True
        index, data = c.kv.get('foo')

        assert c.kv.put('foo', 'bar2', cas=data['ModifyIndex'] - 1) is False
        assert c.kv.put('foo', 'bar2', cas=data['ModifyIndex']) is True
        index, data = c.kv.get('foo')
        assert data['Value'] == six.b('bar2')

    def test_kv_put_flags(self, consul_port):
        c = consul.Consul(port=consul_port)
        c.kv.put('foo', 'bar')
        index, data = c.kv.get('foo')
        assert data['Flags'] == 0

        assert c.kv.put('foo', 'bar', flags=50) is True
        index, data = c.kv.get('foo')
        assert data['Flags'] == 50

    def test_kv_recurse(self, consul_port):
        c = consul.Consul(port=consul_port)
        index, data = c.kv.get('foo/', recurse=True)
        assert data is None

        c.kv.put('foo/', None)
        index, data = c.kv.get('foo/', recurse=True)
        assert len(data) == 1

        c.kv.put('foo/bar1', '1')
        c.kv.put('foo/bar2', '2')
        c.kv.put('foo/bar3', '3')
        index, data = c.kv.get('foo/', recurse=True)
        assert [x['Key'] for x in data] == [
            'foo/', 'foo/bar1', 'foo/bar2', 'foo/bar3']
        assert [x['Value'] for x in data] == [
            None, six.b('1'), six.b('2'), six.b('3')]

    def test_kv_delete(self, consul_port):
        c = consul.Consul(port=consul_port)
        c.kv.put('foo1', '1', dc='dc1')
        c.kv.put('foo2', '2')
        c.kv.put('foo3', '3')
        index, data = c.kv.get('foo', recurse=True, dc='dc1')
        assert [x['Key'] for x in data] == ['foo1', 'foo2', 'foo3']

        assert c.kv.delete('foo2', dc='dc1') is True
        index, data = c.kv.get('foo', recurse=True)
        assert [x['Key'] for x in data] == ['foo1', 'foo3']
        assert c.kv.delete('foo', recurse=True) is True
        index, data = c.kv.get('foo', recurse=True)
        assert data is None

    def test_kv_delete_cas(self, consul_port):
        c = consul.Consul(port=consul_port)

        c.kv.put('foo', 'bar')
        index, data = c.kv.get('foo')

        assert c.kv.delete('foo', cas=data['ModifyIndex'] - 1) is False
        assert c.kv.get('foo') == (index, data)

        assert c.kv.delete('foo', cas=data['ModifyIndex']) is True
        index, data = c.kv.get('foo')
        assert data is None

    def test_kv_acquire_release(self, consul_port):
        c = consul.Consul(port=consul_port)

        pytest.raises(
            consul.ConsulException, c.kv.put, 'foo', 'bar', acquire='foo')

        s1 = c.session.create()
        s2 = c.session.create()

        assert c.kv.put('foo', '1', acquire=s1) is True
        assert c.kv.put('foo', '2', acquire=s2) is False
        assert c.kv.put('foo', '1', acquire=s1) is True
        assert c.kv.put('foo', '1', release='foo') is False
        assert c.kv.put('foo', '2', release=s2) is False
        assert c.kv.put('foo', '2', release=s1) is True

        c.session.destroy(s1)
        c.session.destroy(s2)

    def test_kv_keys_only(self, consul_port):
        c = consul.Consul(port=consul_port)

        assert c.kv.put('bar', '4') is True
        assert c.kv.put('base/foo', '1') is True
        assert c.kv.put('base/base/foo', '5') is True

        index, data = c.kv.get('base/', keys=True, separator='/')
        assert data == ['base/base/', 'base/foo']

    def test_transaction(self, consul_port):
        c = consul.Consul(port=consul_port)
        value = base64.b64encode(b"1").decode("utf8")
        d = {"KV": {"Verb": "set", "Key": "asdf", "Value": value}}
        r = c.txn.put([d])
        assert r["Errors"] is None

        d = {"KV": {"Verb": "get", "Key": "asdf"}}
        r = c.txn.put([d])
        assert r["Results"][0]["KV"]["Value"] == value

    def test_event(self, consul_port):
        c = consul.Consul(port=consul_port)

        assert c.event.fire("fooname", "foobody")
        index, events = c.event.list()
        assert [x['Name'] == 'fooname' for x in events]
        assert [x['Payload'] == 'foobody' for x in events]

    def test_event_targeted(self, consul_port):
        c = consul.Consul(port=consul_port)

        assert c.event.fire("fooname", "foobody")
        index, events = c.event.list(name="othername")
        assert events == []

        index, events = c.event.list(name="fooname")
        assert [x['Name'] == 'fooname' for x in events]
        assert [x['Payload'] == 'foobody' for x in events]

    def test_agent_checks(self, consul_port):
        c = consul.Consul(port=consul_port)

        def verify_and_dereg_check(check_id):
            assert set(c.agent.checks().keys()) == {check_id}
            assert c.agent.check.deregister(check_id) is True
            assert set(c.agent.checks().keys()) == set([])

        def verify_check_status(check_id, status, notes=None):
            checks = c.agent.checks()
            assert checks[check_id]['Status'] == status
            if notes:
                assert checks[check_id]['Output'] == notes

        # test setting notes on a check
        c.agent.check.register('check1', Check.ttl('1s'), notes='foo')
        # c.agent.check.register('check2', script='/usr/bin/true',
        #                        interval=1, notes='foo2')
        c.agent.check.register('check3', ttl=1, notes='foo3')
        c.agent.check.register('check4', http='http://localhost:8500',
                               interval=1, notes='foo4')
        c.agent.check.register('check5', http='http://localhost:8500',
                               timeout=1, interval=1, notes='foo5')
        # c.agent.check.register('check5', Check.ttl('1s'), notes='foo5')
        assert c.agent.checks()['check1']['Notes'] == 'foo'
        c.agent.check.deregister('check1')
        c.agent.check.deregister('check2')
        c.agent.check.deregister('check3')
        c.agent.check.deregister('check4')
        c.agent.check.deregister('check5')

        assert set(c.agent.checks().keys()) == set([])
        assert c.agent.check.register(
            'script_check', Check.script('/bin/true', 10)) is True
        verify_and_dereg_check('script_check')

        assert c.agent.check.register(
            'check name',
            Check.script('/bin/true', 10),
            check_id='check_id') is True

        verify_and_dereg_check('check_id')

        http_addr = "http://127.0.0.1:{0}".format(consul_port)
        assert c.agent.check.register(
            'http_check', Check.http(http_addr, '10ms')) is True
        time.sleep(1)
        verify_check_status('http_check', 'passing')
        verify_and_dereg_check('http_check')

        assert c.agent.check.register(
            'http_timeout_check',
            Check.http(http_addr, '100ms', timeout='2s')) is True
        verify_and_dereg_check('http_timeout_check')

        assert c.agent.check.register('ttl_check', Check.ttl('100ms')) is True

        assert c.agent.check.ttl_warn('ttl_check') is True
        verify_check_status('ttl_check', 'warning')
        assert c.agent.check.ttl_warn(
            'ttl_check', notes='its not quite right') is True
        verify_check_status('ttl_check', 'warning', 'its not quite right')

        assert c.agent.check.ttl_fail('ttl_check') is True
        verify_check_status('ttl_check', 'critical')
        assert c.agent.check.ttl_fail(
            'ttl_check', notes='something went boink!') is True
        verify_check_status(
            'ttl_check', 'critical', notes='something went boink!')

        assert c.agent.check.ttl_pass('ttl_check') is True
        verify_check_status('ttl_check', 'passing')
        assert c.agent.check.ttl_pass(
            'ttl_check', notes='all hunky dory!') is True
        verify_check_status('ttl_check', 'passing', notes='all hunky dory!')
        # wait for ttl to expire
        time.sleep(120 / 1000.0)
        verify_check_status('ttl_check', 'critical')
        verify_and_dereg_check('ttl_check')

    def test_service_dereg_issue_156(self, consul_port):
        # https://github.com/cablehead/python-consul/issues/156
        service_name = 'app#127.0.0.1#3000'
        c = consul.Consul(port=consul_port)
        c.agent.service.register(service_name)

        time.sleep(80 / 1000.0)

        index, nodes = c.health.service(service_name)
        assert [node['Service']['ID'] for node in nodes] == [service_name]

        # Clean up tasks
        assert c.agent.service.deregister(service_name) is True

        time.sleep(40 / 1000.0)

        index, nodes = c.health.service(service_name)
        assert [node['Service']['ID'] for node in nodes] == []

    def test_agent_checks_service_id(self, consul_port):
        c = consul.Consul(port=consul_port)
        c.agent.service.register('foo1')

        time.sleep(40 / 1000.0)

        index, nodes = c.health.service('foo1')
        assert [node['Service']['ID'] for node in nodes] == ['foo1']

        c.agent.check.register('foo', Check.ttl('100ms'), service_id='foo1')

        time.sleep(40 / 1000.0)

        index, nodes = c.health.service('foo1')
        assert set([
            check['ServiceID'] for node in nodes
            for check in node['Checks']]) == {'foo1', ''}
        assert set([
            check['CheckID'] for node in nodes
            for check in node['Checks']]) == {'foo', 'serfHealth'}

        # Clean up tasks
        assert c.agent.check.deregister('foo') is True

        time.sleep(40 / 1000.0)

        assert c.agent.service.deregister('foo1') is True

        time.sleep(40 / 1000.0)

    def test_agent_register_check_no_service_id(self, consul_port):
        c = consul.Consul(port=consul_port)
        index, nodes = c.health.service("foo1")
        assert nodes == []

        pytest.raises(consul.std.base.ConsulException,
                      c.agent.check.register,
                      'foo', Check.ttl('100ms'),
                      service_id='foo1')

        time.sleep(40 / 1000.0)

        assert c.agent.checks() == {}

        # Cleanup tasks
        c.agent.check.deregister('foo')

        time.sleep(40 / 1000.0)

    def test_agent_register_enable_tag_override(self, consul_port):
        c = consul.Consul(port=consul_port)
        index, nodes = c.health.service("foo1")
        assert nodes == []

        c.agent.service.register('foo', enable_tag_override=True)

        assert c.agent.services()['foo']['EnableTagOverride']
        # Cleanup tasks
        c.agent.check.deregister('foo')

    def test_agent_register_enable_weights(self, consul_port):
        c = consul.Consul(port=consul_port)
        index, nodes = c.health.service("foo1")
        assert nodes == []

        c.agent.service.register('foo', weights=Weight.weights(10, 10))
        assert c.agent.services()['foo']['Weights'] == {"Passing": 10, "Warning": 10}
        # Cleanup tasks
        c.agent.check.deregister('foo')

    def test_agent_register_disable_weights(self, consul_port):
        c = consul.Consul(port=consul_port)
        index, nodes = c.health.service("foo1")
        assert nodes == []

        c.agent.service.register('foo')
        assert c.agent.services()['foo']['Weights'] == {"Passing": 1, "Warning": 1}
        # Cleanup tasks
        c.agent.check.deregister('foo')

    def test_agent_service_maintenance(self, consul_port):
        c = consul.Consul(port=consul_port)

        c.agent.service.register('foo', check=Check.ttl('100ms'))

        time.sleep(40 / 1000.0)

        c.agent.service.maintenance('foo', 'true', "test")

        time.sleep(40 / 1000.0)

        checks_pre = c.agent.checks()
        assert '_service_maintenance:foo' in checks_pre.keys()
        assert 'test' == checks_pre['_service_maintenance:foo']['Notes']

        c.agent.service.maintenance('foo', 'false')

        time.sleep(40 / 1000.0)

        checks_post = c.agent.checks()
        assert '_service_maintenance:foo' not in checks_post.keys()

        # Cleanup
        c.agent.service.deregister('foo')

        time.sleep(40 / 1000.0)

    def test_agent_node_maintenance(self, consul_port):
        c = consul.Consul(port=consul_port)

        c.agent.maintenance('true', "test")

        time.sleep(40 / 1000.0)

        checks_pre = c.agent.checks()
        assert '_node_maintenance' in checks_pre.keys()
        assert 'test' == checks_pre['_node_maintenance']['Notes']

        c.agent.maintenance('false')

        time.sleep(40 / 1000.0)

        checks_post = c.agent.checks()
        assert '_node_maintenance' not in checks_post.keys()

    def test_agent_members(self, consul_port):
        c = consul.Consul(port=consul_port)
        members = c.agent.members()
        for x in members:
            assert x['Status'] == 1
            assert not x['Name'] is None
            assert not x['Tags'] is None
        assert c.agent.self()['Member'] in members

        wan_members = c.agent.members(wan=True)
        for x in wan_members:
            assert 'dc1' in x['Name']

    def test_agent_self(self, consul_port):
        c = consul.Consul(port=consul_port)
        assert set(c.agent.self().keys()) == {'Member',
                                              'Stats',
                                              'Config',
                                              'Coord',
                                              'DebugConfig',
                                              'Meta'}

    def test_agent_services(self, consul_port):
        c = consul.Consul(port=consul_port)
        assert c.agent.service.register('foo') is True
        assert set(c.agent.services().keys()) == {'foo'}
        assert c.agent.service.deregister('foo') is True
        assert set(c.agent.services().keys()) == set()

        # test address param
        assert c.agent.service.register('foo',
                                        address='10.10.10.1',
                                        port=8080) is True
        assert [v['Address']
                for k, v in c.agent.services().items()
                if k == 'foo'][0] == '10.10.10.1'
        assert c.agent.service.deregister('foo') is True

    def test_catalog(self, consul_port):
        c = consul.Consul(port=consul_port)

        # grab the node our server created, so we can ignore it
        _, nodes = c.catalog.nodes()
        assert len(nodes) == 1
        current = nodes[0]

        # test catalog.datacenters
        assert c.catalog.datacenters() == ['dc1']

        # test catalog.register
        pytest.raises(
            consul.ConsulException,
            c.catalog.register, 'foo', '10.1.10.11', dc='dc2')

        assert c.catalog.register(
            'n1',
            '10.1.10.11',
            service={'service': 's1'},
            check={'name': 'c1'}) is True

        assert c.catalog.register(
            'n1', '10.1.10.11', service={'service': 's2'}) is True

        assert c.catalog.register(
            'n2', '10.1.10.12',
            service={'service': 's1', 'tags': ['master']}) is True

        assert c.catalog.register(
            'n2', '10.1.10.12',
            service={'service': 's1', 'tags': ['master']},
            node_meta={"a": "b", "c": "d"}
        ) is True

        assert c.catalog.register(
            'n3', '10.1.10.13',
            service={'service': 's3'},
            skipnodeupdate=True
        ) is True

        assert c.catalog.register(
            'n3', '10.1.10.14',
            service={'service': 's3', 'tags': ['foobar']},
            skipnodeupdate=True
        ) is True

        # test catalog.nodes
        pytest.raises(consul.ConsulException, c.catalog.nodes, dc='dc2')
        _, nodes = c.catalog.nodes()
        nodes.remove(current)
        assert [x['Node'] for x in nodes] == ['n1', 'n2', 'n3']

        # test catalog.services
        pytest.raises(consul.ConsulException, c.catalog.services, dc='dc2')
        _, services = c.catalog.services()
        assert services == {'s1': [u'master'],
                            's2': [],
                            's3': [u'foobar'],
                            'consul': []}

        _, services = c.catalog.services(index=current['ModifyIndex'],
                                         wait='10s')
        assert services == {'s1': [u'master'],
                            's2': [],
                            's3': [u'foobar'],
                            'consul': []}

        # test catalog.node
        pytest.raises(consul.ConsulException, c.catalog.node, 'n1', dc='dc2')
        _, node = c.catalog.node('n1')
        assert set(node['Services'].keys()) == {'s1', 's2'}
        _, node = c.catalog.node('n3')
        assert node['Node']['Address'] == '10.1.10.13'
        _, node = c.catalog.node('n4')
        _, node = c.catalog.node('n4',
                                 index=current['ModifyIndex'],
                                 wait='10s')
        assert node is None

        # test catalog.service
        pytest.raises(
            consul.ConsulException, c.catalog.service, 's1', dc='dc2')
        _, nodes = c.catalog.service('s1')
        assert set([x['Node'] for x in nodes]) == {'n1', 'n2'}
        _, nodes = c.catalog.service('s1', tag='master')
        assert set([x['Node'] for x in nodes]) == {'n2'}
        _, nodes = c.catalog.service('s3', tag='foobar')
        assert set([x['Node'] for x in nodes]) == {'n3'}

        # test catalog.deregister
        pytest.raises(
            consul.ConsulException, c.catalog.deregister, 'n2', dc='dc2')
        assert c.catalog.deregister('n1', check_id='c1') is True
        assert c.catalog.deregister('n2', service_id='s1') is True
        # check the nodes weren't removed
        _, nodes = c.catalog.nodes()
        nodes.remove(current)
        assert [x['Node'] for x in nodes] == ['n1', 'n2', 'n3']
        # check n2's s1 service was removed though
        _, nodes = c.catalog.service('s1')
        assert set([x['Node'] for x in nodes]) == {'n1'}

        _, node = c.catalog.service('s2',
                                    near='s2',
                                    index=current['ModifyIndex'],
                                    wait='10s')

        _, nodes = c.catalog.nodes(wait='10s',
                                   near='n1',
                                   index=nodes[0]['ModifyIndex'])
        # cleanup
        assert c.catalog.deregister('n1') is True
        assert c.catalog.deregister('n2') is True
        assert c.catalog.deregister('n3') is True
        _, nodes = c.catalog.nodes()
        nodes.remove(current)
        assert [x['Node'] for x in nodes] == []

    def test_health_service(self, consul_port):
        c = consul.Consul(port=consul_port)

        # check there are no nodes for the service 'foo'
        index, nodes = c.health.service('foo')
        assert nodes == []

        # register two nodes, one with a long ttl, the other shorter
        c.agent.service.register(
            'foo',
            service_id='foo:1',
            check=Check.ttl('10s'),
            tags=['tag:foo:1'])
        c.agent.service.register(
            'foo', service_id='foo:2', check=Check.ttl('100ms'))

        time.sleep(40 / 1000.0)

        # check the nodes show for the /health/service endpoint
        index, nodes = c.health.service('foo')
        assert [node['Service']['ID'] for node in nodes] == ['foo:1', 'foo:2']

        # but that they aren't passing their health check
        index, nodes = c.health.service('foo', passing=True)
        assert nodes == []

        # ping the two node's health check
        c.agent.check.ttl_pass('service:foo:1')
        c.agent.check.ttl_pass('service:foo:2')

        time.sleep(40 / 1000.0)

        # both nodes are now available
        index, nodes = c.health.service('foo', passing=True)
        assert [node['Service']['ID'] for node in nodes] == ['foo:1', 'foo:2']

        # wait until the short ttl node fails
        time.sleep(120 / 1000.0)

        # only one node available
        index, nodes = c.health.service('foo', passing=True)
        assert [node['Service']['ID'] for node in nodes] == ['foo:1']

        # ping the failed node's health check
        c.agent.check.ttl_pass('service:foo:2')

        time.sleep(40 / 1000.0)

        # check both nodes are available
        index, nodes = c.health.service('foo', passing=True)
        assert [node['Service']['ID'] for node in nodes] == ['foo:1', 'foo:2']

        # check that tag works
        index, nodes = c.health.service('foo', tag='tag:foo:1')
        assert [node['Service']['ID'] for node in nodes] == ['foo:1']

        # deregister the nodes
        c.agent.service.deregister('foo:1')
        c.agent.service.deregister('foo:2')

        time.sleep(40 / 1000.0)

        index, nodes = c.health.service('foo')
        assert nodes == []

    def test_health_state(self, consul_port):
        c = consul.Consul(port=consul_port)

        # The empty string is for the Serf Health Status check, which has an
        # empty ServiceID
        index, nodes = c.health.state('any')
        assert [node['ServiceID'] for node in nodes] == ['']

        # register two nodes, one with a long ttl, the other shorter
        c.agent.service.register(
            'foo', service_id='foo:1', check=Check.ttl('10s'))
        c.agent.service.register(
            'foo', service_id='foo:2', check=Check.ttl('100ms'))

        time.sleep(40 / 1000.0)

        # check the nodes show for the /health/state/any endpoint
        index, nodes = c.health.state('any')
        assert set([node['ServiceID']
                    for node in nodes]) == {'', 'foo:1', 'foo:2'}

        # but that they aren't passing their health check
        # continuation line over-indented for visual indent
        index, nodes = c.health.state('passing')
        assert [node['ServiceID'] for node in nodes] != 'foo'

        # ping the two node's health check
        c.agent.check.ttl_pass('service:foo:1')
        c.agent.check.ttl_pass('service:foo:2')

        time.sleep(40 / 1000.0)

        # both nodes are now available
        index, nodes = c.health.state('passing')
        assert set([node['ServiceID']
                    for node in nodes]) == {'', 'foo:1', 'foo:2'}

        # wait until the short ttl node fails
        time.sleep(2200 / 1000.0)

        # only one node available
        index, nodes = c.health.state('passing')
        assert set([node['ServiceID'] for node in nodes]) == {'', 'foo:1'}

        # ping the failed node's health check
        c.agent.check.ttl_pass('service:foo:2')

        time.sleep(40 / 1000.0)

        # check both nodes are available
        index, nodes = c.health.state('passing')
        assert set([node['ServiceID']
                    for node in nodes]) == {'', 'foo:1', 'foo:2'}

        # deregister the nodes
        c.agent.service.deregister('foo:1')
        c.agent.service.deregister('foo:2')

        time.sleep(40 / 1000.0)

        index, nodes = c.health.state('any')
        assert [node['ServiceID'] for node in nodes] == ['']

    def test_health_node(self, consul_port):
        c = consul.Consul(port=consul_port)
        # grab local node name
        node = c.agent.self()['Config']['NodeName']
        index, checks = c.health.node(node)
        assert node in [check["Node"] for check in checks]

    def test_agent_node_join(self, consul_port):
        c = consul.Consul(port=consul_port)
        c.agent.maintenance('true', "test")
        assert c.agent.join(address='127.0.0.1', wan=True) is True
        checks_pre = c.agent.checks()
        assert c.agent.force_leave(
            node=checks_pre['_node_maintenance']['Node']) is True

    def test_health_checks(self, consul_port):
        c = consul.Consul(port=consul_port)

        c.agent.service.register(
            'foobar', service_id='foobar', check=Check.ttl('10s'))

        time.sleep(40 / 1000.00)

        index, checks = c.health.checks('foobar')

        assert [check['ServiceID'] for check in checks] == ['foobar']
        assert [check['CheckID'] for check in checks] == ['service:foobar']

        c.agent.service.register(
            'foobar',
            address='127.0.0.1',
            port=50051,
            service_id='foobar',
            check=Check.grpc(grpc="127.0.0.1:50051/foobar",
                             interval="1s"))
        time.sleep(1)

        _, checks = c.health.checks('foobar')
        assert checks[0]['Status'] == 'critical'
        c.agent.service.deregister('foobar')

        time.sleep(40 / 1000.0)

        index, checks = c.health.checks('foobar')
        assert len(checks) == 0

    def test_session(self, consul_port):
        c = consul.Consul(port=consul_port)

        # session.create
        pytest.raises(consul.ConsulException, c.session.create, node='n2')
        pytest.raises(consul.ConsulException, c.session.create, dc='dc2')
        session_id = c.session.create('my-session')

        # session.list
        pytest.raises(consul.ConsulException, c.session.list, dc='dc2')
        _, sessions = c.session.list()
        assert [x['Name'] for x in sessions] == ['my-session']

        # session.info
        pytest.raises(
            consul.ConsulException, c.session.info, session_id, dc='dc2')
        index, session = c.session.info('1' * 36)
        assert session is None
        index, session = c.session.info(session_id)
        assert session['Name'] == 'my-session'

        # session.node
        node = session['Node']
        pytest.raises(
            consul.ConsulException, c.session.node, node, dc='dc2')
        _, sessions = c.session.node(node)
        assert [x['Name'] for x in sessions] == ['my-session']

        # session.destroy
        pytest.raises(
            consul.ConsulException, c.session.destroy, session_id, dc='dc2')
        assert c.session.destroy(session_id) is True
        _, sessions = c.session.list()
        assert sessions == []

    def test_session_delete_ttl_renew(self, consul_port):
        c = consul.Consul(port=consul_port)

        s = c.session.create(behavior='delete', ttl=20)

        # attempt to renew an unknown session
        pytest.raises(consul.NotFound, c.session.renew, '1' * 36)

        session = c.session.renew(s)
        assert session['Behavior'] == 'delete'
        assert session['TTL'] == '20s'

        # trying out the behavior
        assert c.kv.put('foo', '1', acquire=s) is True
        index, data = c.kv.get('foo')
        assert data['Value'] == six.b('1')

        c.session.destroy(s)
        index, data = c.kv.get('foo')
        assert data is None

    def test_acl_disabled(self, consul_port):
        c = consul.Consul(port=consul_port)
        pytest.raises(consul.ACLDisabled, c.acl.list)
        pytest.raises(consul.ACLDisabled, c.acl.info, '1' * 36)
        pytest.raises(consul.ACLDisabled, c.acl.create)
        pytest.raises(consul.ACLDisabled, c.acl.update, 'foo')
        pytest.raises(consul.ACLDisabled, c.acl.clone, 'foo')
        pytest.raises(consul.ACLDisabled, c.acl.destroy, 'foo')
        pytest.raises(consul.ACLDisabled, c.acl.login,
                      "auth_method", "bearer_token")
        pytest.raises(consul.ACLDisabled, c.acl.logout)

    def test_acl_auth_method(self, consul_port):
        c = consul.Consul(port=consul_port)
        pytest.raises(consul.ACLDisabled, c.acl.auth_method.list)
        pytest.raises(consul.ACLDisabled, c.acl.auth_method.delete, 'foo')
        pytest.raises(consul.ACLDisabled, c.acl.auth_method.get, 'foo')
        pytest.raises(consul.ACLDisabled, c.acl.auth_method.update, None, None)
        pytest.raises(consul.ACLDisabled, c.acl.auth_method.create, None)

    def test_acl_binding_rule(self, consul_port):
        c = consul.Consul(port=consul_port)
        pytest.raises(consul.ACLDisabled, c.acl.binding_rule.list)
        pytest.raises(consul.ACLDisabled, c.acl.binding_rule.delete, 'foo')
        pytest.raises(consul.ACLDisabled, c.acl.binding_rule.get, 'foo')
        pytest.raises(consul.ACLDisabled,
                      c.acl.binding_rule.update, None, None)
        pytest.raises(consul.ACLDisabled, c.acl.binding_rule.create, None)

    def test_status_leader(self, consul_port):
        c = consul.Consul(port=consul_port)

        agent_self = c.agent.self()
        leader = c.status.leader()
        addr_port = agent_self['Stats']['consul']['leader_addr']

        assert leader == addr_port, \
            "Leader value was {0}, expected value " \
            "was {1}".format(leader, addr_port)

    def test_status_peers(self, consul_port):

        c = consul.Consul(port=consul_port)

        agent_self = c.agent.self()

        addr_port = agent_self['Stats']['consul']['leader_addr']
        peers = c.status.peers()

        assert addr_port in peers, \
            "Expected value '{0}' " \
            "in peer list but it was not present".format(addr_port)

    def test_query(self, consul_port):
        c = consul.Consul(port=consul_port)

        # check that query list is empty
        queries = c.query.list(dc='dc1')
        assert queries == []

        # create a new named query
        query_service = 'foo'
        query_name = 'fooquery'
        query = c.query.create(query_service, query_name, 'dc1')

        # assert response contains query ID
        assert 'ID' in query \
               and query['ID'] is not None \
               and str(query['ID']) != ''

        # retrieve query using id and name
        queries = c.query.get(query['ID'], dc='dc1')
        assert queries != [] and len(queries) == 1
        name_ = queries[0]['Name'] == query_name
        id_ = queries[0]['ID'] == query['ID']
        assert name_ and id_

        # explain query
        assert c.query.explain(query_name, dc='dc1')['Query']

        # execute query
        assert c.query.execute(query_name, dc='dc1')

        # delete query
        assert c.query.delete(query['ID'], dc='dc1')

    def test_coordinate(self, consul_port):
        c = consul.Consul(port=consul_port)
        _, nodes = c.catalog.nodes()
        assert len(nodes) == 1
        current = nodes[0]
        c.coordinate.nodes('dc1',
                           index=current['ModifyIndex'],
                           wait='1s',
                           consistency='stale')
        c.coordinate.datacenters()
        assert set(c.coordinate.datacenters()[0].keys()) == {
            'Datacenter',
            'Coordinates',
            'AreaID'
        }

    def test_operator(self, consul_port):
        c = consul.Consul(port=consul_port)
        config = c.operator.raft_config()
        # assert config["Index"] == 0 fixme compatibility trouble
        leader = False
        voter = False
        for server in config["Servers"]:
            if server["Leader"]:
                leader = True
            if server["Voter"]:
                voter = True
        assert leader
        assert voter

    def test_config(self, consul_port):
        c = consul.Consul(port=consul_port)
        payload = {
            "Kind": "service-defaults",
            "Name": "web",
            "Protocol": "http",
        }
        assert c.config.put(payload)

        config = c.config.get(kind=payload['Kind'], name=payload['Name'])
        assert config['Kind'] == 'service-defaults'
        assert config['Name'] == 'web'
        assert config['Protocol'] == 'http'

        configs = c.config.list(kind=payload['Kind'])
        assert configs[0]['Kind'] == 'service-defaults'
        assert configs[0]['Name'] == 'web'
        assert configs[0]['Protocol'] == 'http'

        is_del = c.config.delete(kind=payload['Kind'], name=payload['Name'])

        assert is_del
        config = c.config.get(kind=payload['Kind'], name=payload['Name'])
        assert config[1] is None

    def test_connect(self, consul_port):

        c = consul.Consul(port=consul_port)
        one_root_name = c.connect.certificates.list()['Roots'][0]['Name']
        assert one_root_name == 'Consul CA Root Cert'
        assert c.connect.certificates.current()['Provider'] == 'consul'
        config = {
            "LeafCertTTL": "72h",
            "PrivateKey": """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvhOI639ZxhUSCtUycUDNSgrlcJoMebPPEYzhP6R0tGgTA/iK
mZfQkH5KiI6+DSbPOm+4XAKl0uhRc/IzO93G9cey9WECRR/4MvErWx26AWVIikKi
HigielCZkDBM8UwdVGuCJEteePr0MCHZufBb+n/dJCIQoW8zAxrf17j6psGUIQ4q
vMHe1NoeUTRDyQRvifTfPnal+Du01WWmo4xSSNwmz0P2BMK7dKUqSWO/+tjvqsRM
PJ3iK4RdKrFNxYtEvXs1oxmnuAA5N5+N3dp40YINwNS6U8HDyenRdoDz9+L00rKr
4LqfxT/7fhsUWTp66NSCJ5FB+HvVNOVMYJCdcQIDAQABAoIBAFKbJsxCIn/ltFuk
4DE8GnvtVF2ldXqG3J0h/tqr3FRzTqBRKdsqkWfamwXSE2Kf1TvuRc8nD24jrRKY
1g9UiR1T1sCxkkz8Yd+x1EfbGXV10RrVbqNwidtin/p8I1RS4gRIXNztLHejiPBK
JdebUD4Dx9XmQBgIvcDBszqLl9NUWRP7WIAlJIDGWB97dOMNUIkfVoCMB2sRtB9S
NhCAOhCWU2ogiAK/VltLSKuMFS4O+JA7L0tVIRVTNzTV0qgUhwEN+jzXOxr+o3ME
h+OS3HvKadnogjm763+z1lSkltmV2aBSLkQ/rdrGYdowOROukSWBGvBLAVADKQNe
KAiLRukCgYEA9C9Zntb9nqaB6vUUbw3UBg4l1ZOvP7TT7okPi2gALcQGvXJszyM7
6iYVZzc5WDMlJDF2rK2NmSc0r0PxDtod5Yx6+NZNJxEoIqSlQ9EuZb6StAXKWwUp
j+MddQQYrWJ/XRNoyVw/3AeXJGJ/bbyOEdGQdAD1fR/d8E4x60LBcLsCgYEAx0X0
yhBkO9BEYflQBaPapqcmkUyPflwPCHWpKYkKXe2BhC3ecvHtRbvFRxTIjdWmimzG
qWe6TQ6y50yTxu3OtB1zr/wLlO1Lnh5GpO/CdFZyHPMx9G+ZACa6VKQRRnAr/89u
21K4w4n+XZ5+FiM6oZuNCPFvaDSPpdFVmkG2zcMCgYEAs7VFV8kRznjslGbaKwEa
UXqIDa8rAs+qSZtFfWuE9imWbEaSHb/okGKGzfeulGLPqttcY6k21Mgt1e9CsZOE
/TNuLURKc74Es7pIhqikZOzkOukoC+S4udSEEWJ6ZuBeq7llHQxvUxei/HwhHDnw
tNxuW3F5OiUByaFCy8nNY5ECgYB+bp9CeSXvYVORyeoAuhZneFQbCjVc2bHcDzMW
HFHMiH2NTMD/swl1Hg6r677XZr/0wdFF+H8WlwXhhQ+ZvpZQZwNYnBUJF4nLt6/g
xBJfV92tCoweZ5PuqaO9Qh+HznHMK2NNmm2J+wq9gWrERvPTR2szSmQB/J9LeMbU
SW9fmwKBgQDcZK4R3w+WdUGnmbAPlz2x28Ehfzt39C/9QYC6UIKaZhSgdC5VAT22
ggrb4edVeP4mYaHoEJWzhyPiH4ya0FPJyqD0TVnSPR5tLSGW8Co3M8ctUuTZGWYf
Hc0PLtVZSiTaTGz8MXYhOIdqthRl/MkkGeW/ixMHRzafJ0fxaBVegQ==
-----END RSA PRIVATE KEY-----""",
            "RootCert": """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKCHvfmguKnYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTkxMDA5MDQyMDAyWhcNMjAxMDA4MDQyMDAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEApW4SAb1x/+M4djJV1J8RJUb6j3UI3ODE7dJc+byLSG8eUA/aPVKtyQeD
V4qQsTEJgcK+uv/bca0AfSDpNdKHENTEl7FezfgG5gPHFSu/L/uayclDxDygqIXi
dUQDg675vEYmnqXVudZsvj0zoxiyOt+GfTpAemVzNtOfnfo03rZsnhkmSgcPChCc
ib5Bd+0zanq70OeGG6bBm0wRTfizBhDxsKlTS/f8TKhw/7EtN4kPpVLQ/5RACECg
Qhh4lYXcAjapPsUZvPXwpdCW8uLoon4+QoIx8celiMTjoKj0489zEjtAQd0fqzva
oD048hWF6W5YEMyHzbOkHXhpx2nVMQIDAQABo1AwTjAdBgNVHQ4EFgQUtRUXLy5w
dLPpjjg+wFiqVkdY0FQwHwYDVR0jBBgwFoAUtRUXLy5wdLPpjjg+wFiqVkdY0FQw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAArs06sJ5VPDdDOiwyOWv
q7PRH4advgGI9ZoN/oRB1N2Aeh2RJHFLXBIAYD+3fftSLl1Xm+5HzIevM/djBkC2
cDL6oqvxD8yiPNFJYvqFa+ffrNzmo++x719rnf01rEoh7VXGA1TA8HMMsrocdZv+
xj8sx/WrPu5w2+C+o8f/eAXjFn0ZOz1/iUhziwEJG1BbCV6VEF4rooNdbFzgPLPe
Jro/qF2xNGo/D60lfuDHzbJmTC8BvXoYF8YQMrW3ggJPa0TdXX22zElk/G1T00Ls
mVAOExDtOAOnv2drQ07st0ZAjrLKX5eHYImwYit1tdYXHZdWPsgp0plA15cMw/3y
JA==
-----END CERTIFICATE-----
""",
            "RotationPeriod": "2160h"
        }
        assert c.connect.certificates.put(provider='consul', config=config)

        intention = c.connect.intentions.create(source_name='web',
                                                source_type='consul',
                                                destination_name='db',
                                                action='allow')
        intentions = c.connect.intentions.list()
        assert intentions[0]['ID'] == intention['ID']
        intention = c.connect.intentions.get(intention['ID'])
        assert intention['ID'] == intention['ID']

        assert c.connect.intentions.put(intentions[0]['ID'], source_name='web',
                                        source_type='consul',
                                        destination_name='db',
                                        action='allow')

        assert c.connect.intentions.check(source='web',
                                          destination='db') == {
                   'Allowed': True
               }
        match_list = c.connect.intentions.list_match(by='source',
                                                     name='web')
        assert match_list['web'][0]['SourceName'] == 'web'

        assert match_list['web'][0]['DestinationName'] == 'db'

        assert c.connect.intentions.delete(
            intentions[0]['ID']
        )
        assert c.connect.intentions.list() == []

    def test_snapshot(self, consul_port):
        c = consul.Consul(port=consul_port)
        current_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '.'))
        assert c.snapshot.save(os.path.join(current_path, 'snapshot'))
        assert c.snapshot.restore(os.path.join(current_path, 'snapshot'))
        pytest.raises(consul.ConsulException,
                      c.snapshot.restore,
                      os.path.join(current_path, 'test_std.py'))

    def test_agent_connect(self, consul_port):
        c = consul.Consul(port=consul_port)
        root_ca = c.agent.connect.root_certificates()
        assert root_ca['Roots'][0]['Name'] == 'Consul CA Root Cert'
        # assert root_ca['Roots'][0]['Active'] fixme

        db_ca = c.agent.connect.authorize('db',
                                          'spiffe://dc1-7e567ac2-551d-463f-849'
                                          '7-f78972856fc1.consul/ns/default/dc'
                                          '/dc1/svc/web',
                                          '04:00:00:00:00:01:15:4b:5a:c3:94')
        assert db_ca['Authorized']

        db_ca = c.agent.connect.leaf_certificates('db')
        assert db_ca == (None, None)

    def test_operator_autopilot(self, consul_port):
        time.sleep(2)  # http code 429 Too Many Requests
        c = consul.Consul(port=consul_port)
        assert c.operator.autopilot.configuration()['MaxTrailingLogs'] == 250
        assert not c.operator.autopilot.health()['FailureTolerance']
        payload = {
            "CleanupDeadServers": True,
            "LastContactThreshold": "200ms",
            "MaxTrailingLogs": 251,
            "ServerStabilizationTime": "10s",
            "RedundancyZoneTag": "",
            "DisableUpgradeMigration": False,
            "UpgradeVersionTag": "",
            "CreateIndex": 4,
            "ModifyIndex": 4
        }
        assert c.operator.autopilot.update(payload)

        config = c.operator.autopilot.configuration()

        assert config['MaxTrailingLogs'] == 251

    def test_operator_keyring(self, consul_port):
        c = consul.Consul(port=consul_port)
        Key = "pUqJrVyVRj5jsiYEkM/tFQYfWyJIv4s3XkvDwy7Cu5s="
        Key2 = "pUqJrVyVRj5jsiYEkM/tFQYfWyJIv4s3XkvDwy7Cu55="
        assert c.operator.keyring.create(Key)
        assert Key in {list(keyring['Keys'].keys())
                       [0] for keyring in c.operator.keyring.list()}
        pytest.raises(consul.ConsulException, c.operator.keyring.update, Key2)
        pytest.raises(consul.ConsulException, c.operator.keyring.delete, Key)

    def test_raft(self, consul_port):
        c = consul.Consul(port=consul_port)

        config = c.operator.raft.configuration()
        assert config['Servers'][0]['Leader']

        raft_id = config['Servers'][0]['ID']

        # Need at least one voter in configuration
        pytest.raises(consul.base.ConsulException,
                      c.operator.raft.delete, raft_id)
