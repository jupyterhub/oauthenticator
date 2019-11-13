# How to make a release

`oauthenticator` is a package [available on
PyPI](https://pypi.org/project/oauthenticator/) and
[conda-forge](https://conda-forge.org/). These are instructions on how to make a
release on PyPI.

For you to follow along according to these instructions, you need:
- To be a maintainer of the [PyPI oauthenticator
  project](https://pypi.org/project/oauthenticator/).
- To have push rights to the [oauthenticator GitHub
  repository](https://github.com/jupyterhub/oauthenticator).

## Steps to make a release

1. Checkout master and make sure it is up to date.

   ```
   git checkout master
   git fetch <upstream> master
   git reset --hard <upstream>/master
   ```

1. Update [CHANGELOG.md](CHANGELOG.md). Doing this can be made easier with the
   help of the
   [choldgraf/github-activity](https://github.com/choldgraf/github-activity)
   utility.

1. Set the `version_info` variable in [_version.py](oauthenticator/_version.py)
   appropriately and make a commit with message `release <tag>`.

1. Create a git tag for the commit.

   ```
   git tag -a $TAG -m $TAG
   ```

1. Package the release
   ```
   python3 setup.py sdist bdist_wheel
   ```

1. Upload it to PyPI
   ```
   twine upload dist/*
   ```

1. Reset the `version_info` variable in
   [_version.py](oauthenticator/_version.py) appropriately with a `dev` element
   and make a commit with the message `back to dev`.

1. Push your two commits to master along with the annotated tags referencing
   commits on master.

   ```
   git push --follow-tags <upstream> master
   ```

1. Following the release to PyPI, an automated PR should arrive to
   [conda-forge/oauthenticator-feedstock](https://github.com/conda-forge/oauthenticator-feedstock),
   check for the tests to succeed on this PR and then merge it to successfully
   update the package for `conda` on the conda-forge channel.
