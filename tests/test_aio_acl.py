import asyncio

import pytest

import consul.aio


@pytest.fixture
def loop(request):
    asyncio.set_event_loop(None)
    loop = asyncio.new_event_loop()

    def fin():
        loop.close()

    request.addfinalizer(fin)
    return loop


class TestAsyncioConsulACL(object):
    def test_acl(self, loop, acl_consul):
        async def main():
            c = consul.aio.Consul(
                port=acl_consul.port, token=acl_consul.token, loop=loop)

            rules = """
            key "" {
                policy = "read"
            }
            key "private/" {
                policy = "deny"
            }
            """
            token = await c.acl.create(rules=rules)

            try:
                await c.acl.list(token=token)
            except consul.ACLPermissionDenied:
                raised = True
            assert raised

            token = await c.acl.create(rules=rules, name='foo', acl_id='foo-1')

            try:
                await c.acl.list(token=token)
            except consul.ACLPermissionDenied:
                raised = True
            assert raised

            token = await c.acl.create(type=None)

            try:
                await c.acl.list(token=token)
            except consul.ACLPermissionDenied:
                raised = True
            assert raised

            destroyed = await c.acl.destroy(token)
            assert destroyed is True
            query_service = 'foo'
            query_name = 'fooquery'
            query = await c.query.create(query_service,
                                         query_name,
                                         token=acl_consul.token)
            await c.query.update(query['ID'],
                                 query_name,
                                 token=acl_consul.token)

            # assert response contains query ID
            assert 'ID' in query \
                   and query['ID'] is not None \
                   and str(query['ID']) != ''

        loop.run_until_complete(main())
