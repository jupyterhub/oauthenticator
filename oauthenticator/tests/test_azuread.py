from pytest import mark
from ..azuread import AzureAdOAuthenticator

_t_id = 'XXX-XXX-XXXX'


class Config(object):
    tenant_id = _t_id


@mark.gen_test
def test_getTenant_with_tenant_id():
    t_id = AzureAdOAuthenticator.getTenant(Config())
    assert t_id == _t_id


import os
os.environ["AAD_TENANT_ID"] = "some_random_id"


@mark.gen_test
def test_getTenant_from_vars():
    t_id = AzureAdOAuthenticator.getTenant(object)
    assert t_id.default_value == "some_random_id"
