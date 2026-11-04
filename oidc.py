"""OIDC Authorization Code + PKCE relying-party flow for enterprise SSO."""
from __future__ import annotations
import base64,hashlib,secrets,time
from urllib.parse import urlencode
import requests
import jwt
from jwt import PyJWKClient

class OIDCError(RuntimeError): pass

class OIDCClient:
    def __init__(self,issuer,client_id,client_secret,redirect_uri,tenant_id=None,timeout=8):
        self.issuer=issuer.rstrip("/")
        self.client_id=client_id
        self.client_secret=client_secret
        self.redirect_uri=redirect_uri
        self.tenant_id=tenant_id
        self.timeout=timeout
        if not self.issuer.startswith("https://"):
            raise OIDCError("OIDC issuer must use HTTPS")
        if not all((client_id,client_secret,redirect_uri)):
            raise OIDCError("OIDC client credentials and redirect URI are required")
        if not redirect_uri.startswith("https://") and "localhost" not in redirect_uri and "127.0.0.1" not in redirect_uri:
            raise OIDCError("OIDC redirect URI must use HTTPS")

    def discovery(self):
        response=requests.get(self.issuer+"/.well-known/openid-configuration",timeout=self.timeout)
        response.raise_for_status()
        doc=response.json()
        if doc.get("issuer")!=self.issuer:
            raise OIDCError("discovery issuer does not match configured issuer")
        for field in ("authorization_endpoint","token_endpoint","jwks_uri"):
            if not str(doc.get(field,"")).startswith("https://"):
                raise OIDCError("OIDC discovery contains a non-HTTPS endpoint")
        return doc

    @staticmethod
    def pkce_pair():
        verifier=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        return verifier,challenge

    def begin(self):
        doc=self.discovery()
        state=secrets.token_urlsafe(32)
        nonce=secrets.token_urlsafe(32)
        verifier,challenge=self.pkce_pair()
        params={"response_type":"code","client_id":self.client_id,"redirect_uri":self.redirect_uri,
                "scope":"openid profile email","state":state,"nonce":nonce,
                "code_challenge":challenge,"code_challenge_method":"S256"}
        return doc["authorization_endpoint"]+"?"+urlencode(params),state,nonce,verifier

    def complete(self,code,verifier,nonce):
        if not code or len(code)>4096: raise OIDCError("invalid authorization code")
        doc=self.discovery()
        response=requests.post(doc["token_endpoint"],data={
            "grant_type":"authorization_code","code":code,"redirect_uri":self.redirect_uri,
            "client_id":self.client_id,"code_verifier":verifier
        },auth=(self.client_id,self.client_secret),timeout=self.timeout)
        response.raise_for_status()
        token=response.json().get("id_token")
        if not token: raise OIDCError("token response has no ID token")
        try:
            signing_key=PyJWKClient(doc["jwks_uri"],timeout=self.timeout).get_signing_key_from_jwt(token).key
            claims=jwt.decode(token,signing_key,algorithms=["RS256","ES256"],
                audience=self.client_id,issuer=self.issuer,
                options={"require":["exp","iat","iss","aud","sub","nonce"]},leeway=60)
        except Exception as exc:
            raise OIDCError("ID token signature or claims validation failed") from exc
        if not secrets.compare_digest(str(claims.get("nonce","")),nonce):
            raise OIDCError("OIDC nonce validation failed")
        if self.tenant_id and claims.get("tid")!=self.tenant_id:
            raise OIDCError("OIDC tenant is not allowed")
        subject=claims.get("sub")
        if not isinstance(subject,str) or not subject or len(subject)>512:
            raise OIDCError("OIDC subject is invalid")
        if __import__("os").getenv("SENTINEL_OIDC_REQUIRE_MFA")=="1" and "mfa" not in claims.get("amr",[]):
            raise OIDCError("identity provider did not assert MFA")
        return {"issuer":self.issuer,"subject":subject,"claims":claims}

def oidc_client_from_env():
    import os
    names=("SENTINEL_OIDC_ISSUER","SENTINEL_OIDC_CLIENT_ID","SENTINEL_OIDC_CLIENT_SECRET","SENTINEL_OIDC_REDIRECT_URI")
    values=[os.getenv(name,"") for name in names]
    if not all(values): raise OIDCError("enterprise SSO is not configured")
    return OIDCClient(*values,tenant_id=os.getenv("SENTINEL_OIDC_TENANT_ID"))
