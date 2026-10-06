import unittest
from starlette.testclient import TestClient
from silk_live.config import Settings
from silk_live.runtime import build_from_environment


class RuntimeTests(unittest.TestCase):
    def test_empty_configuration_is_fail_closed(self):
        with TestClient(build_from_environment({})) as c:
            self.assertFalse(c.get('/health').json()['configured'])
            self.assertEqual(c.post('/mcp',json={}).status_code,503)
    def test_partial_configuration_is_not_a_connection(self):
        with TestClient(build_from_environment({'SILK_POSTGRES_DSN':'private-synthetic-placeholder'})) as c:
            r=c.get('/health');self.assertFalse(r.json()['configured']);self.assertNotIn('private-synthetic',r.text)
    def test_http_resource_or_url_credentials_forbidden(self):
        for resource in ['http://silk.example/mcp','https://user:password@silk.example/mcp','https://silk.example/mcp?token=x','https://silk.example/not-mcp']:
            with self.subTest(resource=resource),self.assertRaises(ValueError):
                Settings('https://auth.example/',''+resource,'https://auth.example/jwks',('client',))
    def test_noncanonical_issuer_discovery_mismatch_forbidden(self):
        with self.assertRaises(ValueError):Settings('https://auth.example','https://silk.example/mcp','https://auth.example/jwks',('client',))
    def test_no_client_or_wildcard_origins(self):
        for clients,origins in [((),()),(('client',),('https://*.example',))]:
            with self.assertRaises(ValueError):Settings('https://auth.example/','https://silk.example/mcp','https://auth.example/jwks',clients,origins)
    def test_invalid_full_configuration_fails_closed_without_echo(self):
        env={'SILK_ISSUER_URL':'http://auth.invalid','SILK_RESOURCE_URL':'https://silk.example/mcp','SILK_JWKS_URL':'https://auth.example/jwks','SILK_ALLOWED_CLIENT_IDS':'client','SILK_POSTGRES_DSN':'PRIVATE_SYNTHETIC_VALUE'}
        with TestClient(build_from_environment(env)) as c:
            r=c.get('/health');self.assertFalse(r.json()['configured']);self.assertNotIn('PRIVATE',r.text)


if __name__=='__main__':unittest.main()
