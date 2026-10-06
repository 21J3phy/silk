import time
import unittest
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

from silk_live.app import create_app, MAX_BODY
from silk_live.config import Settings
from silk_live.domain import MailboxError

SETTINGS = Settings(issuer_url="https://auth.example/", resource_url="https://silk.example/mcp", jwks_url="https://auth.example/jwks", allowed_client_ids=("test-client",))
HEADERS = {"Authorization": "Bearer synthetic-test-token", "Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25"}


class FixtureVerifier:
    async def verify_token(self, token):
        if token not in {"synthetic-test-token", "without-scope"}:
            return None
        return AccessToken(token=token, client_id="test-client", subject="test-subject", scopes=["silk:mailbox"] if token == "synthetic-test-token" else [], expires_at=int(time.time())+300, resource=SETTINGS.resource_url, claims={"iss": SETTINGS.issuer_url, "sub": "test-subject", "client_id": "test-client"})


class FixtureStore:
    durable_for_deployment = False
    def __init__(self): self.calls=[]
    def record(self, method, principal, *args):
        self.calls.append((method,principal,args));return {"agent_id":"bound-agent-001","operation":method}
    def identity(self,p,n):return self.record("identity",p,n)
    def send(self,p,d,n):return self.record("send",p,d,n)
    def receive(self,p,l,n):return self.record("receive",p,l,n)
    def ack(self,p,d,n):return self.record("ack",p,d,n)
    def receipts(self,p,l,n):return self.record("receipts",p,l,n)
    def revoke(self,p,g,n):return self.record("revoke",p,g,n)


class MCPTransportTests(unittest.TestCase):
    def setUp(self):
        self.store=FixtureStore()
        self.client=TestClient(create_app(SETTINGS,self.store,FixtureVerifier(),testing=True),base_url="https://silk.example")
        self.client.__enter__()
    def tearDown(self):self.client.__exit__(None,None,None)
    def rpc(self,method,params=None,headers=None,id=1):
        body={"jsonrpc":"2.0","id":id,"method":method}
        if params is not None:body["params"]=params
        return self.client.post("/mcp",json=body,headers=HEADERS if headers is None else headers)
    def test_initialize_official_sdk_profile(self):
        r=self.rpc("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture-test","version":"1"}})
        self.assertEqual(r.status_code,200,r.text)
        result=r.json()["result"]
        self.assertEqual(result["protocolVersion"],"2025-11-25")
        self.assertIn("tools",result["capabilities"])
        self.assertNotIn("mcp-session-id",r.headers)
    def test_tools_list_six_explicit_mailbox_tools(self):
        r=self.rpc("tools/list")
        self.assertEqual(r.status_code,200,r.text)
        tools={x["name"]:x for x in r.json()["result"]["tools"]}
        self.assertEqual(set(tools),{"silk_identity","silk_send","silk_receive","silk_ack","silk_receipts","silk_revoke"})
        self.assertNotIn("sender_agent_id",tools["silk_send"]["inputSchema"]["properties"])
        self.assertFalse(tools["silk_send"]["annotations"]["readOnlyHint"])
    def test_authenticated_identity_uses_token_binding(self):
        r=self.rpc("tools/call",{"name":"silk_identity","arguments":{}})
        self.assertEqual(r.status_code,200,r.text)
        self.assertFalse(r.json()["result"].get("isError",False),r.text)
        self.assertEqual(self.store.calls[0][1].subject,"test-subject")
        self.assertEqual(self.store.calls[0][1].client_id,"test-client")
    def test_sender_body_spoof_rejected_before_store(self):
        r=self.rpc("tools/call",{"name":"silk_identity","arguments":{"subject":"other-owner"}})
        self.assertEqual(r.status_code,400)
        self.assertEqual(self.store.calls,[])
    def test_no_token_challenge_has_protected_resource_metadata(self):
        r=self.rpc("tools/list",headers={k:v for k,v in HEADERS.items() if k!="Authorization"})
        self.assertEqual(r.status_code,401,r.text)
        self.assertIn("resource_metadata=",r.headers["www-authenticate"])
        self.assertEqual(self.store.calls,[])
    def test_wrong_token_is_unauthorized(self):
        r=self.rpc("tools/list",headers={**HEADERS,"Authorization":"Bearer wrong"})
        self.assertEqual(r.status_code,401)
    def test_missing_scope_is_forbidden(self):
        r=self.rpc("tools/list",headers={**HEADERS,"Authorization":"Bearer without-scope"})
        self.assertEqual(r.status_code,403,r.text)
    def test_metadata_is_public_and_correctly_bound(self):
        r=self.client.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()["resource"],SETTINGS.resource_url)
        self.assertEqual(r.json()["authorization_servers"],[SETTINGS.issuer_url])
        self.assertEqual(r.json()["scopes_supported"],["silk:mailbox"])
    def test_origin_and_host_denied(self):
        for headers in ({**HEADERS,"Origin":"https://evil.example"},{**HEADERS,"Host":"evil.example"},{**HEADERS,"Origin":"null"}):
            with self.subTest(headers=headers):self.assertEqual(self.rpc("tools/list",headers=headers).status_code,403)
        self.assertEqual(self.store.calls,[])
    def test_duplicate_json_keys_nonfinite_invalid_utf8(self):
        for body in [b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"tools/list"}',b'{"jsonrpc":"2.0","id":NaN,"method":"tools/list"}',b'\xff']:
            with self.subTest(body=body):self.assertEqual(self.client.post("/mcp",content=body,headers=HEADERS).status_code,400)
    def test_body_size_bound(self):
        self.assertEqual(self.client.post("/mcp",content=b' '* (MAX_BODY+1),headers=HEADERS).status_code,413)
    def test_url_credentials_rejected(self):
        r=self.client.post("/mcp?access_token=synthetic",json={"jsonrpc":"2.0","id":1,"method":"tools/list"},headers=HEADERS)
        self.assertEqual(r.status_code,400)
    def test_accept_and_content_type_requirements(self):
        r=self.rpc("tools/list",headers={**HEADERS,"Accept":"application/json"})
        self.assertEqual(r.status_code,406,r.text)
        r=self.client.post("/mcp",content='{"jsonrpc":"2.0","id":1,"method":"tools/list"}',headers={**HEADERS,"Content-Type":"text/plain"})
        self.assertEqual(r.status_code,415,r.text)
    def test_unknown_method_returns_bounded_jsonrpc_method_error(self):
        r=self.rpc("unsupported/method")
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()["error"]["code"],-32601)
        self.assertEqual(self.store.calls,[])
    def test_unsupported_protocol_version_rejected(self):
        self.assertEqual(self.rpc("tools/list",headers={**HEADERS,"MCP-Protocol-Version":"not-a-version"}).status_code,400)
    def test_notification_accepted_without_response_body(self):
        r=self.client.post("/mcp",json={"jsonrpc":"2.0","method":"notifications/initialized"},headers=HEADERS)
        self.assertEqual(r.status_code,202,r.text);self.assertEqual(r.content,b"")
    def test_no_get_stream_or_sessions(self):
        r=self.client.get("/mcp",headers={**HEADERS,"Accept":"text/event-stream"})
        self.assertEqual(r.status_code,405,r.text)
    def test_tool_schema_strict_integer_rejects_bool(self):
        r=self.rpc("tools/call",{"name":"silk_receive","arguments":{"limit":True}})
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()["result"]["isError"])
        self.assertEqual(self.store.calls,[])
    def test_internal_failures_do_not_echo_sensitive_exception(self):
        def fail(*a):raise RuntimeError("SECRET-DSN-or-message")
        self.store.identity=fail
        r=self.rpc("tools/call",{"name":"silk_identity","arguments":{}})
        self.assertEqual(r.status_code,200,r.text)
        self.assertNotIn("SECRET",r.text);self.assertIn("mailbox_unavailable",r.text)
    def test_domain_error_is_bounded_tool_failure(self):
        def fail(*a):raise MailboxError("grant_inactive","Permission is inactive.")
        self.store.identity=fail
        r=self.rpc("tools/call",{"name":"silk_identity","arguments":{}})
        self.assertTrue(r.json()["result"]["isError"]);self.assertIn("grant_inactive",r.text)
    def test_response_security_headers(self):
        r=self.rpc("tools/list")
        self.assertEqual(r.headers["cache-control"],"no-store")
        self.assertEqual(r.headers["x-content-type-options"],"nosniff")
    def test_default_app_fails_closed(self):
        with TestClient(create_app()) as client:
            self.assertFalse(client.get("/health").json()["configured"])
            self.assertEqual(client.post("/mcp",json={"jsonrpc":"2.0","id":1,"method":"tools/list"}).status_code,503)
    def test_fixture_store_cannot_be_used_for_deployment(self):
        with self.assertRaises(ValueError):create_app(SETTINGS,self.store,FixtureVerifier())


if __name__=="__main__":unittest.main()
