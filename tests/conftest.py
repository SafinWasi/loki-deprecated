"""
conftest
"""

import pytest, responses

@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    monkeypatch.setenv("HOST", "https://test.org")
    monkeypatch.setenv("CLIENT_ID", "abcdef")
    monkeypatch.setenv("CLIENT_SECRET", "abcdef")

@pytest.fixture(scope="function")
def test_loki(mocked_responses, openid_response):
    from main.loki import Loki
    mocked_responses.get(
        "https://example.org/.well-known/openid-configuration",
        json=openid_response,
        status=200,
        content_type="application/json"
    )
    return Loki("https://example.org", "abcdef", "abcdef")

@pytest.fixture
def mocked_responses():
    with responses.RequestsMock() as rsps:
        yield rsps

@pytest.fixture()
def openid_response():
    return {
        "request_parameter_supported" : True,
        "pushed_authorization_request_endpoint" : "https://example.org/par",
        "introspection_endpoint" : "https://example.org/introspection",
        "claims_parameter_supported" : False,
        "issuer" : "https://example.org",
        "userinfo_encryption_enc_values_supported" : [ "A128CBC+HS256", "A256CBC+HS512", "A128GCM", "A256GCM" ],
        "id_token_encryption_enc_values_supported" : [ "A128CBC+HS256", "A256CBC+HS512", "A128GCM", "A256GCM" ],
        "access_token_signing_alg_values_supported" : [ "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES512", "PS256", "PS384", "PS512" ],
        "authorization_endpoint" : "https://example.org/authorize",
        "service_documentation" : "http://jans.org/docs",
        "authorization_encryption_alg_values_supported" : [ "RSA1_5", "RSA-OAEP", "A128KW", "A256KW" ],
        "claims_supported" : [ "street_address", "country", "zoneinfo", "birthdate", "role", "gender", "user_name", "formatted", "phone_mobile_number", "preferred_username", "inum", "locale", "updated_at", "post_office_box", "nickname", "preferred_language", "email", "website", "email_verified", "profile", "locality", "room_number", "phone_number_verified", "given_name", "middle_name", "picture", "o", "name", "phone_number", "postal_code", "region", "family_name", "jansAdminUIRole" ],
        "ssa_endpoint" : "https://example.org/ssa",
        "token_endpoint_auth_methods_supported" : [ "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth" ],
        "tls_client_certificate_bound_access_tokens" : True,
        "response_modes_supported" : [ "query.jwt", "fragment", "form_post.jwt", "fragment.jwt", "form_post", "query", "jwt" ],
        "backchannel_logout_session_supported" : True,
        "token_endpoint" : "https://example.org/token",
        "response_types_supported" : [ "token", "id_token code", "token code", "token id_token", "token id_token code", "id_token", "code" ],
        "authorization_encryption_enc_values_supported" : [ "A128CBC+HS256", "A256CBC+HS512", "A128GCM", "A256GCM" ],
        "backchannel_token_delivery_modes_supported" : [ "poll", "ping", "push" ],
        "dpop_signing_alg_values_supported" : [ "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" ],
        "request_uri_parameter_supported" : True,
        "backchannel_user_code_parameter_supported" : False,
        "grant_types_supported" : [ "client_credentials", "urn:ietf:params:oauth:grant-type:uma-ticket", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:device_code", "authorization_code", "password", "refresh_token", "implicit" ],
        "ui_locales_supported" : [ "en", "bg", "de", "es", "fr", "it", "ru", "tr" ],
        "userinfo_endpoint" : "https://example.org/userinfo",
        "op_tos_uri" : "https://example.org/tos",
        "require_request_uri_registration" : False,
        "id_token_encryption_alg_values_supported" : [ "RSA1_5", "RSA-OAEP", "A128KW", "A256KW" ],
        "frontchannel_logout_session_supported" : True,
        "authorization_signing_alg_values_supported" : [ "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "ES512", "PS256", "PS384", "PS512" ],
        "claims_locales_supported" : [ "en" ],
        "clientinfo_endpoint" : "https://example.org/clientinfo",
        "request_object_signing_alg_values_supported" : [ "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" ],
        "request_object_encryption_alg_values_supported" : [ "RSA1_5", "RSA-OAEP", "A128KW", "A256KW" ],
        "session_revocation_endpoint" : "https://example.org/revoke_session",
        "check_session_iframe" : "https://example.org/jans-auth/opiframe.htm",
        "scopes_supported" : ["openid", "profile"],
        "backchannel_logout_supported" : True,
        "acr_values_supported" : [ "casa", "github_ads", "basic_alias2", "basic_alias1", "agama", "fido2", "otp", "basic" ],
        "request_object_encryption_enc_values_supported" : [ "A128CBC+HS256", "A256CBC+HS512", "A128GCM", "A256GCM" ],
        "device_authorization_endpoint" : "https://example.org/device_authorization",
        "display_values_supported" : [ "page", "popup" ],
        "userinfo_signing_alg_values_supported" : [ "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" ],
        "require_pushed_authorization_requests" : False,
        "claim_types_supported" : [ "normal" ],
        "userinfo_encryption_alg_values_supported" : [ "RSA1_5", "RSA-OAEP", "A128KW", "A256KW" ],
        "end_session_endpoint" : "https://example.org/end_session",
        "revocation_endpoint" : "https://example.org/revoke",
        "backchannel_authentication_endpoint" : "https://example.org/bc-authorize",
        "token_endpoint_auth_signing_alg_values_supported" : [ "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" ],
        "frontchannel_logout_supported" : True,
        "jwks_uri" : "https://example.org/jwks",
        "subject_types_supported" : [ "public", "pairwise" ],
        "id_token_signing_alg_values_supported" : [ "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" ],
        "registration_endpoint" : "https://example.org/register",
        "id_token_token_binding_cnf_values_supported" : [ "tbh" ]
    }

