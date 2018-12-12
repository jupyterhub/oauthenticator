from pytest import mark
from ..azuread import AzureAdOAuthenticator

_t_id = 'XXX-XXX-XXXX'


class Config(object):
    tenant_id = _t_id


def test_gettenant_with_tenant_id():
    t_id = AzureAdOAuthenticator.get_tenant(Config())
    assert t_id == _t_id


import os
os.environ["AAD_TENANT_ID"] = "some_random_id"


def test_gettenant_from_env():
    t_id = AzureAdOAuthenticator.get_tenant(object)
    assert t_id.default_value == "some_random_id"
