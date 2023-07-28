# Configuration file for Sphinx to build our documentation to HTML.
#
import datetime
import os
import sys

import oauthenticator

# -- Project information -----------------------------------------------------
# ref: https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
#
project = 'OAuthenticator'
copyright = f"{datetime.date.today().year}, Project Jupyter Contributors"
author = "Project Jupyter Contributors"
version = '%i.%i' % oauthenticator.version_info[:2]
release = oauthenticator.__version__

# -- Generate config reference documents based on entrypoints ----------------
#
# source/reference/api includes two templates, index.rst.tpl and
# authenticator.rst.tpl. They are used to generate an index.rst file and a file
# for each authenticator.
#
from collections import defaultdict

if sys.version_info < (3, 10):
    from importlib_metadata import entry_points
else:
    from importlib.metadata import entry_points

import jinja2

# The generation relies on the sphinx extension sphinx.ext.autodoc, and since it
# loads python files it can error if it tries to import an optional dependency
# we haven't installed. Because of this, we mock those dependencies using this
# config option.
autodoc_mock_imports = ["jwt", "mwoauth", "globus_sdk"]


def render_autodoc_modules():
    authenticator_entrypoints = entry_points(group="jupyterhub.authenticators")

    here = os.path.dirname(__file__)
    api = os.path.join(here, "reference/api")
    api_gen = os.path.join(api, "gen")

    # modules is a dict of dicts of lists
    # { '$module': { 'classes': [...], 'configurables': [...] } }

    modules = defaultdict(lambda: defaultdict(list))

    # pre-load base classes
    modules['oauthenticator.oauth2'] = {
        'classes': [
            'OAuthLoginHandler',
            'OAuthCallbackHandler',
        ],
        'configurables': [
            'OAuthenticator',
        ],
    }

    # load Authenticator classes from entrypoints
    for ep in authenticator_entrypoints:
        if ep.value and ep.value.startswith('oauthenticator.'):
            module_name, _, object_name = ep.value.partition(":")
            modules[module_name]['configurables'].append(object_name)

    with open(os.path.join(api, "authenticator.rst.tpl")) as f:
        tpl = jinja2.Template(f.read())

    try:
        os.makedirs(os.path.join(api_gen))
    except FileExistsError:
        pass

    for mod, mod_content in modules.items():
        dest = os.path.join(api_gen, mod + ".rst")
        print(
            f"Autogenerating module documentation in {dest} with classes: {mod_content}"
        )

        with open(dest, "w") as f:
            f.write(tpl.render(module=mod, **mod_content))

    # render the module index
    with open(os.path.join(api, "index.rst.tpl")) as f:
        index_tpl = jinja2.Template(f.read())

    with open(os.path.join(api, "index.rst"), "w") as f:
        f.write(index_tpl.render(modules=modules))


render_autodoc_modules()


# -- Add versionremoved directive ---------------------------------------------------
# ref: https://github.com/sphinx-doc/sphinx/issues/11480
#
from sphinx.domains.changeset import VersionChange, versionlabel_classes, versionlabels


def setup(app):
    if "versionremoved" not in versionlabels:
        versionlabels["versionremoved"] = "Removed in version %s"
        versionlabel_classes["versionremoved"] = "removed"
        app.add_directive("versionremoved", VersionChange)


# -- General Sphinx configuration --------------------------------------------
# ref: https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
#
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
    'sphinx.ext.napoleon',
    'sphinxext.rediraffe',
    'autodoc_traits',
    'myst_parser',
    'sphinx_copybutton',
]

root_doc = "index"
source_suffix = [".md", ".rst"]

# default_role is set for use with reStructuredText that we still need to use in
# docstrings in the autodoc_traits inspected Python module. It makes single
# backticks around text, like `my_function`, behave as in typical Markdown.
default_role = "literal"

# Disable autosummary otherwise it will overwrite the oauthenticators docs in the `gen` directory.
# Reference: https://www.sphinx-doc.org/en/master/usage/extensions/autosummary.html#confval-autosummary_generate
autosummary_generate = False


# -- Options for intersphinx extension ---------------------------------------
# ref: https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html#configuration
#
# The extension makes us able to link like to other projects like below.
#
#     rST  - :external:py:class:`tornado.httpclient.AsyncHTTPClient`
#     MyST - {external:py:class}`tornado.httpclient.AsyncHTTPClient`
#
# To see what we can link to, do the following where "objects.inv" is appended
# to the sphinx based website:
#
#     python -m sphinx.ext.intersphinx https://www.tornadoweb.org/en/stable/objects.inv
#
intersphinx_mapping = {
    "tornado": ("https://www.tornadoweb.org/en/stable/", None),
    "jupyterhub": ("https://jupyterhub.readthedocs.io/en/stable/", None),
}

# intersphinx_disabled_reftypes set based on recommendation in
# https://docs.readthedocs.io/en/stable/guides/intersphinx.html#using-intersphinx
intersphinx_disabled_reftypes = ["*"]


# -- Options for HTML output -------------------------------------------------
# ref: https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output
#
html_title = 'OAuthenticator'
html_theme = 'sphinx_book_theme'
html_theme_options = {
    "repository_url": "https://github.com/jupyterhub/oauthenticator",
    "use_issues_button": True,
    "use_repository_button": True,
    "use_edit_page_button": True,
}

html_logo = '_static/images/logo/logo.png'
html_favicon = '_static/images/logo/favicon.ico'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files, so
# a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]


# -- Options for linkcheck builder -------------------------------------------
# ref: https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-the-linkcheck-builder
#
linkcheck_ignore = [
    r"(.*)github\.com(.*)#",  # javascript based anchors
    r"(.*)/#%21(.*)/(.*)",  # /#!forum/jupyter - encoded anchor edge case
    r"https://github.com/[^/]*$",  # too many github usernames / searches in changelog
    "https://github.com/jupyterhub/oauthenticator/pull/",  # too many pull requests in changelog
    "https://github.com/jupyterhub/oauthenticator/compare/",  # too many ref comparisons in changelog
    "https://github.com/settings/applications/new",  # sign-in redirect noise
    "https://admin.google.com/",  # sign-in redirect noise
    "https://console.cloud.google.com",  # sign-in redirect noise
    "https://console.developers.google.com",  # sign-in redirect noise
]
linkcheck_anchors_ignore = [
    "/#!",
    "/#%21",
]

# -- Options for the rediraffe extension -------------------------------------
# ref: https://github.com/wpilibsuite/sphinxext-rediraffe#readme
#
# This extensions help us relocated content without breaking links. If a
# document is moved internally, put its path as a dictionary key in the
# redirects dictionary below and its new location in the value.
#
rediraffe_branch = "main"
rediraffe_redirects = {
    "getting-started": "tutorials/general-setup",
    "install": "tutorials/install",
    "changelog": "reference/changelog",
    "cilogon": "topic/cilogon",
    "extending": "topic/extending",
    "google": "topic/google",
    "github": "topic/github",
    "gitlab": "topic/gitlab",
    "migrations": "how-to/migrations/upgrade-to-15",
    "api/gen/oauthenticator.oauth2": "reference/api/gen/oauthenticator.oauth2",
    "api/gen/oauthenticator.auth0": "reference/api/gen/oauthenticator.auth0",
    "api/gen/oauthenticator.azuread": "reference/api/gen/oauthenticator.azuread",
    "api/gen/oauthenticator.bitbucket": "reference/api/gen/oauthenticator.bitbucket",
    "api/gen/oauthenticator.cilogon": "reference/api/gen/oauthenticator.cilogon",
    "api/gen/oauthenticator.generic": "reference/api/gen/oauthenticator.generic",
    "api/gen/oauthenticator.github": "reference/api/gen/oauthenticator.github",
    "api/gen/oauthenticator.gitlab": "reference/api/gen/oauthenticator.gitlab",
    "api/gen/oauthenticator.globus": "reference/api/gen/oauthenticator.globus",
    "api/gen/oauthenticator.google": "reference/api/gen/oauthenticator.google",
    "api/gen/oauthenticator.okpy": "reference/api/gen/oauthenticator.okpy",
    "api/gen/oauthenticator.openshift": "reference/api/gen/oauthenticator.openshift",
    "api/gen/oauthenticator.mediawiki": "reference/api/gen/oauthenticator.mediawiki",
    # 2023-06-29 docs refresh
    "topic/cilogon": "tutorials/provider-specific-setup/providers/cilogon",
    "tutorials/provider-specific-setup/providers/awscognito": "tutorials/provider-specific-setup/providers/generic",
}
