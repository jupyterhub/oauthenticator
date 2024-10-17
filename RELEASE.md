# How to make a release

`oauthenticator` is a package available on [PyPI] and on [conda-forge].

These are the instructions on how to make a release.

## Pre-requisites

- Push rights to this GitHub repository

## Steps to make a release

1. Create a PR updating `docs/source/reference/changelog.md` with
   [github-activity] and continue when its merged. For details about this, see
   the [team-compass documentation] about it.

2. Checkout main and make sure it is up to date.

   ```shell
   git checkout main
   git fetch origin main
   git reset --hard origin/main
   ```

3. Update the version, make commits, and push a git tag with `tbump`.

   ```shell
   pip install tbump
   ```

   `tbump` will ask for confirmation before doing anything.

   ```shell
   # Example versions to set: 1.0.0, 1.0.0b1
   VERSION=
   tbump ${VERSION}
   ```

   Following this, the [CI system] will build and publish a release.

4. Reset the version back to dev, e.g. `1.0.1.dev` after releasing `1.0.0`.

   ```shell
   # Example version to set: 1.0.1.dev
   NEXT_VERSION=
   tbump --no-tag ${NEXT_VERSION}.dev
   ```

5. Following the release to PyPI, an automated PR should arrive within 24 hours
   to [conda-forge/oauthenticator-feedstock] with instructions on releasing to
   conda-forge. You are welcome to volunteer doing this, but aren't required as
   part of making this release to PyPI.

[github-activity]: https://github.com/executablebooks/github-activity
[team-compass documentation]: https://jupyterhub-team-compass.readthedocs.io/en/latest/practices/releases.html
[pypi]: https://pypi.org/project/oauthenticator/
[ci system]: https://github.com/jupyterhub/oauthenticator/actions/workflows/release.yaml
[conda-forge]: https://anaconda.org/conda-forge/oauthenticator
[conda-forge/oauthenticator-feedstock]: https://github.com/conda-forge/oauthenticator-feedstock
