from pytest import mark
from ..azuread import AzureAdOAuthenticator

import os
os.environ["AAD_TENANT_ID"] = "some_random_id"


def test_tenant_id_from_env():
    aad = AzureAdOAuthenticator()
    assert aad.tenant_id == "some_random_id"
