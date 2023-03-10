import base64
import datetime
import uuid

import jwt
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from oauthenticator.azureadcert import AzureAdOAuthenticatorWithCertificate

client_id = '{AAD-APP-CLIENT-ID}'
tenant_id = '{AAD-APP-TENANT-ID}'
certificate_name = '{CERTIFICATE-NAME}'
keyvault_name = '{KEYVAULT-NAME}'

c.JupyterHub.authenticator_class = AzureAdOAuthenticatorWithCertificate
c.AzureAdOAuthenticatorWithCertificate.tenant_id = tenant_id
c.AzureAdOAuthenticatorWithCertificate.oauth_callback_url = (
    'http://localhost:8000/hub/oauth_callback'
)
c.AzureAdOAuthenticatorWithCertificate.client_id = client_id
c.AzureAdOAuthenticatorWithCertificate.username_claim = 'unique_name'
c.AzureAdOAuthenticatorWithCertificate.scope = f'{client_id}/.default'

try:
    user_credential = DefaultAzureCredential()
    secret_client = SecretClient(
        vault_url=f'https://{keyvault_name}.vault.azure.net/',
        credential=user_credential,
    )
    certificate_secret = secret_client.get_secret(name=certificate_name)
    cert_bytes = base64.b64decode(certificate_secret.value)

    (
        private_key,
        public_certificate,
        additional_certificates,
    ) = pkcs12.load_key_and_certificates(data=cert_bytes, password=None)

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    b64sha1cert = base64.b64encode(
        public_certificate.fingerprint(hashes.SHA1())
    ).decode()

    def jwthandler(handler, data):
        exp_time = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
            seconds=600
        )
        nbf_time = datetime.datetime.now(tz=datetime.timezone.utc)

        jwt_headers = {"alg": "RS256", "typ": "JWT", "x5t": b64sha1cert}

        jwt_payload = {
            "iss": client_id,
            "sub": client_id,
            "exp": exp_time,
            "nbf": nbf_time,
            "jti": str(uuid.uuid1()),
            "aud": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        }

        encdata = jwt.encode(
            algorithm="RS256",
            key=private_bytes,
            payload=jwt_payload,
            headers=jwt_headers,
        )

        return encdata

    c.AzureAdOAuthenticatorWithCertificate.client_assertion_handler = jwthandler

except:
    print("Client certificate environment support parameters need to be setup.")
