import json,unittest
from unittest.mock import patch
from urllib.parse import urlparse,parse_qs
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from oidc import OIDCClient,OIDCError

class FakeResponse:
 def __init__(self,data): self.data=data
 def raise_for_status(self): pass
 def json(self): return self.data

class OIDCTests(unittest.TestCase):
 def setUp(self):
  self.issuer="https://idp.example.test"
  self.discovery={"issuer":self.issuer,"authorization_endpoint":self.issuer+"/authorize",
   "token_endpoint":self.issuer+"/token","jwks_uri":self.issuer+"/jwks"}
  self.client=OIDCClient(self.issuer,"client-id","client-secret","https://app.example.test/auth/oidc/callback",tenant_id="tenant-a")
  self.private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 def token(self,nonce,tenant="tenant-a",amr=None):
  claims={"iss":self.issuer,"sub":"immutable-subject-42","aud":"client-id","iat":1700000000,
   "exp":4102444800,"nonce":nonce,"tid":tenant,"amr":amr or ["mfa"]}
  return jwt.encode(claims,self.private,algorithm="RS256",headers={"kid":"unit-test-key"})
 def test_authorization_uses_state_nonce_and_s256_pkce(self):
  with patch("oidc.requests.get",return_value=FakeResponse(self.discovery)):
   url,state,nonce,verifier=self.client.begin()
  query=parse_qs(urlparse(url).query)
  self.assertEqual(query["state"],[state]);self.assertEqual(query["nonce"],[nonce])
  self.assertEqual(query["code_challenge_method"],["S256"])
  self.assertNotEqual(query["code_challenge"],[verifier])
 def test_callback_validates_signed_id_token_and_tenant(self):
  nonce="random-nonce";token=self.token(nonce)
  with patch("oidc.requests.get",return_value=FakeResponse(self.discovery)),patch("oidc.requests.post",return_value=FakeResponse({"id_token":token})),patch("oidc.PyJWKClient") as jwks:
   jwks.return_value.get_signing_key_from_jwt.return_value.key=self.private.public_key()
   result=self.client.complete("authorization-code","verifier",nonce)
  self.assertEqual(result["subject"],"immutable-subject-42")
  with patch("oidc.requests.get",return_value=FakeResponse(self.discovery)),patch("oidc.requests.post",return_value=FakeResponse({"id_token":self.token("different-nonce")})),patch("oidc.PyJWKClient") as jwks:
   jwks.return_value.get_signing_key_from_jwt.return_value.key=self.private.public_key()
   with self.assertRaises(OIDCError):self.client.complete("authorization-code","verifier",nonce)
 def test_unapproved_tenant_is_rejected(self):
  with patch("oidc.requests.get",return_value=FakeResponse(self.discovery)),patch("oidc.requests.post",return_value=FakeResponse({"id_token":self.token("n","tenant-b")})),patch("oidc.PyJWKClient") as jwks:
   jwks.return_value.get_signing_key_from_jwt.return_value.key=self.private.public_key()
   with self.assertRaises(OIDCError):self.client.complete("authorization-code","verifier","n")
 def test_configured_mfa_assurance_is_required(self):
  from unittest.mock import patch
  token=self.token("n",amr=["pwd"])
  with patch.dict("os.environ",{"SENTINEL_OIDC_REQUIRE_MFA":"1"}),patch("oidc.requests.get",return_value=FakeResponse(self.discovery)),patch("oidc.requests.post",return_value=FakeResponse({"id_token":token})),patch("oidc.PyJWKClient") as jwks:
   jwks.return_value.get_signing_key_from_jwt.return_value.key=self.private.public_key()
   with self.assertRaises(OIDCError):self.client.complete("code","verifier","n")
 def test_invalid_signature_is_rejected(self):
  token=self.token("n")
  other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  with patch("oidc.requests.get",return_value=FakeResponse(self.discovery)),patch("oidc.requests.post",return_value=FakeResponse({"id_token":token})),patch("oidc.PyJWKClient") as jwks:
   jwks.return_value.get_signing_key_from_jwt.return_value.key=other.public_key()
   with self.assertRaises(OIDCError):self.client.complete("code","verifier","n")
 def test_discovery_issuer_mismatch_fails_closed(self):
  bad={**self.discovery,"issuer":"https://attacker.example"}
  with patch("oidc.requests.get",return_value=FakeResponse(bad)):
   with self.assertRaises(OIDCError):self.client.begin()

if __name__=="__main__":unittest.main()
