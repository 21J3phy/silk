"""Official SDK client -> ASGI transport -> real verifier -> fixture SQL store.

These are disposable local clients, never Grok, dot, or a real OAuth provider.
"""
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import time
import unittest

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from silk_live.app import create_app
from silk_live.auth import JWTAccessTokenVerifier
from silk_live.config import Settings
from silk_live.domain import Principal
from silk_live.storage import SQLiteFixtureStore


class MCPRoundTripTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='silk-mcp-roundtrip-')
        self.now=int(time.time())
        self.settings=Settings('https://auth.example/','https://silk.example/mcp','https://auth.example/jwks',('client-alpha','client-beta'))
        self.store=SQLiteFixtureStore(Path(self.directory.name)/'fixture.sqlite3')
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()));jwk.update(kid='fixture-key',alg='RS256',use='sig',key_ops=['verify'])
        self.jwks=json.dumps({'keys':[jwk]}).encode()
        async def fetcher(url):
            self.assertEqual(url,self.settings.jwks_url)
            return self.jwks
        self.verifier=JWTAccessTokenVerifier(issuer=self.settings.issuer_url,resource=self.settings.resource_url,jwks_url=self.settings.jwks_url,allowed_client_ids=set(self.settings.allowed_client_ids),jwks_fetcher=fetcher)
        self.principals={}
        for name in ('alpha','beta'):
            p=Principal(self.settings.issuer_url,'subject-'+name,'client-'+name)
            self.principals[name]=p
            self.store.provision_agent('agent-'+name,'owner-'+name,'Fixture '+name)
            self.store.provision_binding(p,'agent-'+name,expires_at=self.now+3600,now=self.now)
        self.store.provision_grant('grant-alpha-beta','agent-alpha','agent-beta',expires_at=self.now+3600,max_turns=8,now=self.now)
        self.app=create_app(self.settings,self.store,self.verifier,testing=True)
    async def asyncTearDown(self):
        self.directory.cleanup()
    @asynccontextmanager
    async def clients(self):
        async with AsyncExitStack() as stack:
            self.stack=stack
            await stack.enter_async_context(self.app.app.router.lifespan_context(self.app.app))
            self.alpha=await self.client('alpha');self.beta=await self.client('beta')
            yield
    async def client(self,name):
        token=jwt.encode({'iss':self.settings.issuer_url,'aud':self.settings.resource_url,'sub':'subject-'+name,'client_id':'client-'+name,'iat':self.now-1,'exp':self.now+600,'scope':'silk:mailbox'},self.key,algorithm='RS256',headers={'typ':'at+jwt','kid':'fixture-key'})
        client=await self.stack.enter_async_context(httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),headers={'Authorization':'Bearer '+token},timeout=5))
        read,write,_=await self.stack.enter_async_context(streamable_http_client(self.settings.resource_url,http_client=client))
        session=await self.stack.enter_async_context(ClientSession(read,write,read_timeout_seconds=timedelta(seconds=5)))
        init=await session.initialize();self.assertEqual(init.protocolVersion,'2025-11-25')
        return session
    async def call(self,client,name,args=None,ok=True):
        result=await client.call_tool(name,args or {})
        if ok:self.assertFalse(result.isError,result.content)
        else:self.assertTrue(result.isError,result.content)
        if result.structuredContent is not None:return result.structuredContent
        return json.loads(result.content[0].text) if ok else result.content[0].text
    def message(self,key='send-alpha-001',**changes):
        return {'grant_id':'grant-alpha-beta','recipient_agent_id':'agent-beta','text':'Can we coordinate a time? This is untrusted message data.','idempotency_key':key,'ttl_seconds':300,**changes}
    async def test_official_sdk_two_client_roundtrip_and_receipts(self):
        async with self.clients():
            self.assertEqual((await self.call(self.alpha,'silk_identity'))['agent_id'],'agent-alpha')
            self.assertEqual((await self.call(self.beta,'silk_identity'))['agent_id'],'agent-beta')
            sent=await self.call(self.alpha,'silk_send',self.message())
            self.assertEqual(sent['status'],'queued')
            self.assertEqual((await self.call(self.alpha,'silk_receive'))['messages'],[])
            inbox=(await self.call(self.beta,'silk_receive'))['messages']
            self.assertEqual(len(inbox),1);self.assertEqual(inbox[0]['sender_agent_id'],'agent-alpha')
            self.assertEqual(inbox[0]['content_trust'],'untrusted_data')
            receipt=await self.call(self.beta,'silk_ack',{'message_id':sent['message_id'],'idempotency_key':'ack-beta-001','outcome':'received'})
            self.assertEqual(receipt['effect'],'mailbox_acknowledgment_only')
            self.assertEqual((await self.call(self.beta,'silk_receive'))['messages'],[])
            self.assertEqual((await self.call(self.alpha,'silk_receipts'))['receipts'],[receipt])
            reply=await self.call(self.beta,'silk_send',{'grant_id':'grant-alpha-beta','recipient_agent_id':'agent-alpha','text':'Yes. A reply through the same approved pair.','idempotency_key':'send-beta-001','ttl_seconds':300,'reply_to':sent['message_id']})
            inbox=(await self.call(self.alpha,'silk_receive'))['messages']
            self.assertEqual(inbox[0]['message_id'],reply['message_id']);self.assertEqual(inbox[0]['reply_to'],sent['message_id'])
            await self.call(self.alpha,'silk_ack',{'message_id':reply['message_id'],'idempotency_key':'ack-alpha-001','outcome':'received'})
            self.assertEqual(len((await self.call(self.beta,'silk_receipts'))['receipts']),2)
    async def test_client_retry_does_not_consume_another_turn(self):
        async with self.clients():
            first=await self.call(self.alpha,'silk_send',self.message())
            second=await self.call(self.alpha,'silk_send',self.message())
            self.assertEqual(first['message_id'],second['message_id']);self.assertTrue(second['duplicate'])
            identity=await self.call(self.alpha,'silk_identity')
            self.assertEqual(identity['grants'][0]['remaining_turns'],7)
            await self.call(self.alpha,'silk_send',self.message(text='changed payload'),ok=False)
    async def test_revocation_hides_pending_content_and_blocks_send(self):
        async with self.clients():
            await self.call(self.alpha,'silk_send',self.message())
            await self.call(self.beta,'silk_revoke',{'grant_id':'grant-alpha-beta'})
            self.assertEqual((await self.call(self.beta,'silk_receive'))['messages'],[])
            await self.call(self.alpha,'silk_send',self.message(key='send-alpha-002'),ok=False)
    async def test_revoked_binding_blocks_even_still_valid_jwt(self):
        async with self.clients():
            self.store.revoke_binding(self.principals['alpha'],now=int(time.time()))
            await self.call(self.alpha,'silk_identity',ok=False)
            await self.call(self.alpha,'silk_send',self.message(),ok=False)


if __name__=='__main__':unittest.main()
