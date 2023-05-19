# Changelog

For detailed changes from the prior release, click on the version number, and
its link will bring up a GitHub listing of changes. Use `git log` on the
command line for details.

## [Unreleased]

(changelog:version-15)=

## 15.0

### 15.1.0 - 2022-09-08

#### New features added

- [Auth0] Add `auth0_domain` config [#534](https://github.com/jupyterhub/oauthenticator/pull/534) ([@drhagen](https://github.com/drhagen))
- [CILogon] Add allowed_domains to allowed_idps config for a possiblity to restrict access based on idp + domain [#518](https://github.com/jupyterhub/oauthenticator/pull/518) ([@GeorgianaElena](https://github.com/GeorgianaElena))

#### Enhancements made

- [Generic] Allow passing a string separated by periods for `claim_groups_key` [#537](https://github.com/jupyterhub/oauthenticator/pull/537) ([@dingobar](https://github.com/dingobar))

#### Documentation improvements

- Update documentation theme and fix autodoc [#524](https://github.com/jupyterhub/oauthenticator/pull/524) ([@GeorgianaElena](https://github.com/GeorgianaElena))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2022-06-09&to=2022-09-08&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2022-06-09..2022-09-08&type=Issues) | [@dingobar](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adingobar+updated%3A2022-06-09..2022-09-08&type=Issues) | [@drhagen](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adrhagen+updated%3A2022-06-09..2022-09-08&type=Issues) | [@GeorgianaElena](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AGeorgianaElena+updated%3A2022-06-09..2022-09-08&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2022-06-09..2022-09-08&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2022-06-09..2022-09-08&type=Issues) | [@terrencegf](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aterrencegf+updated%3A2022-06-09..2022-09-08&type=Issues) | [@yuvipanda](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ayuvipanda+updated%3A2022-06-09..2022-09-08&type=Issues)

### 15.0.1

#### Bugs fixed

- [Bitbucket] Fix for changes to bitbucket API - /teams removed and /workspaces to be used [#477](https://github.com/jupyterhub/oauthenticator/pull/477) ([@Marcalberga](https://github.com/Marcalberga))
- [CILogon] Don't make action a required field of CILogonOAuthenticator.allowed_idps follow-up [#517](https://github.com/jupyterhub/oauthenticator/pull/517) ([@GeorgianaElena](https://github.com/GeorgianaElena))
- [CILogon] Don't make action a required field of CILogonOAuthenticator.allowed_idps [#516](https://github.com/jupyterhub/oauthenticator/pull/516) ([@GeorgianaElena](https://github.com/GeorgianaElena))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2022-06-03&to=2022-06-09&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2022-06-03..2022-06-09&type=Issues) | [@GeorgianaElena](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AGeorgianaElena+updated%3A2022-06-03..2022-06-09&type=Issues) | [@Marcalberga](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AMarcalberga+updated%3A2022-06-03..2022-06-09&type=Issues) | [@welcome](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Awelcome+updated%3A2022-06-03..2022-06-09&type=Issues)

### 15.0.0

If you are using AzureAD, MediaWiki, and CILogon authenticators, make sure to
read about the breaking changes.

#### Breaking security change

- `CILogonOAuthenticator` has breaking changes and come with a [migration
  guide](migrations:upgrade-to-15).
  These changes resolve the known vulnerability
  [GHSA-r7v4-jwx9-wx43](https://github.com/jupyterhub/oauthenticator/security/advisories/GHSA-r7v4-jwx9-wx43).
  **Your hub will fail to start if you do not follow the migration guide**.

#### Other breaking changes

- `pyjwt` version 2.4.0 or greater is now required when use with authentication
  classes that needs it: `AzureAdOAuthenticator`, `MWOAuthenticator`.

#### New features added

- [GitHub] Add populate_teams_in_auth_state option [#498](https://github.com/jupyterhub/oauthenticator/pull/498) ([@yuvipanda](https://github.com/yuvipanda), [@consideRatio](https://github.com/consideRatio), [@GeorgianaElena](https://github.com/GeorgianaElena), [@manics](https://github.com/manics))

#### Enhancements made

- Allow and document custom 403 messages and pages [#484](https://github.com/jupyterhub/oauthenticator/pull/484) ([@GeorgianaElena](https://github.com/GeorgianaElena), [@yuvipanda](https://github.com/yuvipanda))

#### Bugs fixed

- [GitHub] fix implementation of populate_teams_in_auth_state [#504](https://github.com/jupyterhub/oauthenticator/pull/504) ([@consideRatio](https://github.com/consideRatio), [@yuvipanda](https://github.com/yuvipanda))
- [Auth0] Fix AUTH0_SUBDOMAIN default setting [#502](https://github.com/jupyterhub/oauthenticator/pull/502) ([@alejandrosame](https://github.com/alejandrosame), [@yuvipanda](https://github.com/yuvipanda))

#### Maintenance and upkeep improvements

- maint: unpin extras_require googlegroups dependencies [#508](https://github.com/jupyterhub/oauthenticator/pull/508) ([@consideRatio](https://github.com/consideRatio), [@missingcharacter](https://github.com/missingcharacter))
- breaking maint: require pyjwt>=2 and mwoauth>=0.3.8 (to reduce complexity) [#506](https://github.com/jupyterhub/oauthenticator/pull/506) ([@consideRatio](https://github.com/consideRatio), [@yuvipanda](https://github.com/yuvipanda), [@GeorgianaElena](https://github.com/GeorgianaElena), [@halfak](https://github.com/halfak))
- Use isort for import formatting [#497](https://github.com/jupyterhub/oauthenticator/pull/497) ([@yuvipanda](https://github.com/yuvipanda), [@consideRatio](https://github.com/consideRatio))
- General maintenance and fix of pre-commit ci failure [#479](https://github.com/jupyterhub/oauthenticator/pull/479) ([@consideRatio](https://github.com/consideRatio), [@minrk](https://github.com/minrk), [@GeorgianaElena](https://github.com/GeorgianaElena))
- Remove custom stylesheet and bump sphinx version [#465](https://github.com/jupyterhub/oauthenticator/pull/465) ([@diego-plan9](https://github.com/diego-plan9), [@consideRatio](https://github.com/consideRatio))
- Support pyjwt >= 2 in tests [#461](https://github.com/jupyterhub/oauthenticator/pull/461) ([@diego-plan9](https://github.com/diego-plan9), [@minrk](https://github.com/minrk), [@consideRatio](https://github.com/consideRatio))

#### Documentation improvements

- docs/ci: use myst, fix broken links, add linkcheck test, remove deprecated distutils, avoid 2x job triggers [#511](https://github.com/jupyterhub/oauthenticator/pull/511) ([@consideRatio](https://github.com/consideRatio), [@GeorgianaElena](https://github.com/GeorgianaElena))
- docs/source/getting-started: mention openid scope for AzureAD + MFA [#478](https://github.com/jupyterhub/oauthenticator/pull/478) ([@rkdarst](https://github.com/rkdarst), [@consideRatio](https://github.com/consideRatio))
- Fix My Service authenticator class names in documentation [#457](https://github.com/jupyterhub/oauthenticator/pull/457) ([@sgaist](https://github.com/sgaist), [@consideRatio](https://github.com/consideRatio))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2021-08-10&to=2022-06-02&type=c))

[@alejandrosame](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aalejandrosame+updated%3A2021-08-10..2022-06-02&type=Issues) | [@brianaydemir](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Abrianaydemir+updated%3A2021-08-10..2022-06-02&type=Issues) | [@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2021-08-10..2022-06-02&type=Issues) | [@diego-plan9](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adiego-plan9+updated%3A2021-08-10..2022-06-02&type=Issues) | [@GeorgianaElena](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AGeorgianaElena+updated%3A2021-08-10..2022-06-02&type=Issues) | [@halfak](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ahalfak+updated%3A2021-08-10..2022-06-02&type=Issues) | [@kkaraivanov1](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Akkaraivanov1+updated%3A2021-08-10..2022-06-02&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2021-08-10..2022-06-02&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2021-08-10..2022-06-02&type=Issues) | [@missingcharacter](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amissingcharacter+updated%3A2021-08-10..2022-06-02&type=Issues) | [@rkdarst](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Arkdarst+updated%3A2021-08-10..2022-06-02&type=Issues) | [@sgaist](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asgaist+updated%3A2021-08-10..2022-06-02&type=Issues) | [@yuvipanda](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ayuvipanda+updated%3A2021-08-10..2022-06-02&type=Issues)

## 14.2

### [14.2.0] - 2021-08-09

#### Enhancements made

- [GitHub] Add syntax to allow specific teams in a GitHub organization [#449](https://github.com/jupyterhub/oauthenticator/pull/449) ([@j0nnyr0berts](https://github.com/j0nnyr0berts))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2021-07-19&to=2021-08-09&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2021-07-19..2021-08-09&type=Issues) | [@dhirschfeld](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adhirschfeld+updated%3A2021-07-19..2021-08-09&type=Issues) | [@j0nnyr0berts](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aj0nnyr0berts+updated%3A2021-07-19..2021-08-09&type=Issues) | [@jabbera](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ajabbera+updated%3A2021-07-19..2021-08-09&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2021-07-19..2021-08-09&type=Issues) | [@sgibson91](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asgibson91+updated%3A2021-07-19..2021-08-09&type=Issues)

## 14.1

### [14.1.0] - 2021-07-19

#### New features added

- [Globus] Add config to manage: allowed, admin, and blocked users through Globus groups [#441](https://github.com/jupyterhub/oauthenticator/pull/441) ([@rpwagner](https://github.com/rpwagner))
- [Globus] Add config username_from_email [#440](https://github.com/jupyterhub/oauthenticator/pull/440) ([@rpwagner](https://github.com/rpwagner))
- [Auth0] Add config username_key - maps identity providers response to a JH username [#439](https://github.com/jupyterhub/oauthenticator/pull/439) ([@GeorgianaElena](https://github.com/GeorgianaElena))
- [All] Support custom logout url (logout_redirect_url) [#437](https://github.com/jupyterhub/oauthenticator/pull/437) ([@GeorgianaElena](https://github.com/GeorgianaElena))

#### Bugs fixed

- [GitLab] Fix missing use validate_server_cert config for some web requests [#443](https://github.com/jupyterhub/oauthenticator/pull/443) ([@wOvAN](https://github.com/wOvAN))
- [GitHub] Set JH user's email with non-public email if needed and granted scope to do so [#442](https://github.com/jupyterhub/oauthenticator/pull/442) ([@satra](https://github.com/satra))

#### Maintenance and upkeep improvements

- pre-commit configured and executed [#434](https://github.com/jupyterhub/oauthenticator/pull/434) ([@consideRatio](https://github.com/consideRatio))
- ci: unpin pyjwt in test-requirements.txt [#431](https://github.com/jupyterhub/oauthenticator/pull/431) ([@consideRatio](https://github.com/consideRatio))

#### Documentation improvements

- docs: update to async/await in example [#435](https://github.com/jupyterhub/oauthenticator/pull/435) ([@consideRatio](https://github.com/consideRatio))
- Add reference to external FeiShuAuthenticator [#427](https://github.com/jupyterhub/oauthenticator/pull/427) ([@harrywang](https://github.com/harrywang))
- Note that whitelist should be used if not in 1.2 [#422](https://github.com/jupyterhub/oauthenticator/pull/422) ([@mafloh](https://github.com/mafloh))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2021-04-09&to=2021-07-18&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2021-04-09..2021-07-18&type=Issues) | [@GeorgianaElena](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AGeorgianaElena+updated%3A2021-04-09..2021-07-18&type=Issues) | [@harrywang](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aharrywang+updated%3A2021-04-09..2021-07-18&type=Issues) | [@holdenk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aholdenk+updated%3A2021-04-09..2021-07-18&type=Issues) | [@mafloh](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amafloh+updated%3A2021-04-09..2021-07-18&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2021-04-09..2021-07-18&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2021-04-09..2021-07-18&type=Issues) | [@NickolausDS](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ANickolausDS+updated%3A2021-04-09..2021-07-18&type=Issues) | [@rpwagner](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Arpwagner+updated%3A2021-04-09..2021-07-18&type=Issues) | [@satra](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asatra+updated%3A2021-04-09..2021-07-18&type=Issues) | [@wOvAN](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AwOvAN+updated%3A2021-04-09..2021-07-18&type=Issues)

## 14.0

### [14.0.0] - 2021-04-09

([full changelog](https://github.com/jupyterhub/oauthenticator/compare/0.13.0...14.0.0))

#### New features added

- Support username_claim in Google OAuth [#401](https://github.com/jupyterhub/oauthenticator/pull/401) ([@dtaniwaki](https://github.com/dtaniwaki))
- added allowed_groups and admin_groups to generic.py [#395](https://github.com/jupyterhub/oauthenticator/pull/395) ([@mcmartins](https://github.com/mcmartins))
- [Google] Allow for checking of google_groups for admin only [#358](https://github.com/jupyterhub/oauthenticator/pull/358) ([@dwilliams782](https://github.com/dwilliams782))

#### Enhancements made

- Add `.fetch(req)` method to base OAuthenticator [#415](https://github.com/jupyterhub/oauthenticator/pull/415) ([@minrk](https://github.com/minrk))
- [OpenShift] add allowed_groups and admin_groups [#410](https://github.com/jupyterhub/oauthenticator/pull/410) ([@wseaton](https://github.com/wseaton))
- Clear cookie on logout [#404](https://github.com/jupyterhub/oauthenticator/pull/404) ([@dtaniwaki](https://github.com/dtaniwaki))

#### Bugs fixed

- [azuread] pyjwt 1+2 compatibility, azuread test coverage [#420](https://github.com/jupyterhub/oauthenticator/pull/420) ([@minrk](https://github.com/minrk))

#### Maintenance and upkeep improvements

- Test oldest dependencies and bump jupyterhub required to 1.2 [#413](https://github.com/jupyterhub/oauthenticator/pull/413) ([@consideRatio](https://github.com/consideRatio))
- [Generic] Remove userdata_method configuration supposedly not relevant [#376](https://github.com/jupyterhub/oauthenticator/pull/376) ([@consideRatio](https://github.com/consideRatio))

#### Documentation improvements

- docs: cleanup userdata_method from docs [#416](https://github.com/jupyterhub/oauthenticator/pull/416) ([@consideRatio](https://github.com/consideRatio))
- allowed_project_ids is the valid name [#409](https://github.com/jupyterhub/oauthenticator/pull/409) ([@manning-ncsa](https://github.com/manning-ncsa))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2021-02-04&to=2021-04-09&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2021-02-04..2021-04-09&type=Issues) | [@dhirschfeld](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adhirschfeld+updated%3A2021-02-04..2021-04-09&type=Issues) | [@dtaniwaki](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adtaniwaki+updated%3A2021-02-04..2021-04-09&type=Issues) | [@dwilliams782](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adwilliams782+updated%3A2021-02-04..2021-04-09&type=Issues) | [@holdenk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aholdenk+updated%3A2021-02-04..2021-04-09&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2021-02-04..2021-04-09&type=Issues) | [@manning-ncsa](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanning-ncsa+updated%3A2021-02-04..2021-04-09&type=Issues) | [@mcmartins](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amcmartins+updated%3A2021-02-04..2021-04-09&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2021-02-04..2021-04-09&type=Issues) | [@support](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asupport+updated%3A2021-02-04..2021-04-09&type=Issues) | [@welcome](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Awelcome+updated%3A2021-02-04..2021-04-09&type=Issues) | [@wseaton](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Awseaton+updated%3A2021-02-04..2021-04-09&type=Issues)

## 0.13

### [0.13.0] - 2021-02-04

#### Enhancements made

- Ensure oauthenticator.tests is packaged [#407](https://github.com/jupyterhub/oauthenticator/pull/407) ([@manics](https://github.com/manics))
- Auth0: Add refresh and id tokens to auth_state [#393](https://github.com/jupyterhub/oauthenticator/pull/393) ([@biomath-vlad](https://github.com/biomath-vlad))

#### Bugs fixed

- PyJWT 2.0 compliant [#402](https://github.com/jupyterhub/oauthenticator/pull/402) ([@rragundez](https://github.com/rragundez))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2020-12-04&to=2021-02-04&type=c))

[@biomath-vlad](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Abiomath-vlad+updated%3A2020-12-04..2021-02-04&type=Issues) | [@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2020-12-04..2021-02-04&type=Issues) | [@kianaf](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Akianaf+updated%3A2020-12-04..2021-02-04&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2020-12-04..2021-02-04&type=Issues) | [@rragundez](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Arragundez+updated%3A2020-12-04..2021-02-04&type=Issues) | [@yuvipanda](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ayuvipanda+updated%3A2020-12-04..2021-02-04&type=Issues)

## 0.12

### [0.12.3] - 2020-12-04

#### Bugs fixed

- Fix exception when enable_auth_state is enabled but user.encrypted_auth_state is None [#391](https://github.com/jupyterhub/oauthenticator/pull/391) ([@rkevin-arch](https://github.com/rkevin-arch))

#### Maintenance and upkeep improvements

- typos in test_mediawiki.py [#390](https://github.com/jupyterhub/oauthenticator/pull/390) ([@minrk](https://github.com/minrk))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2020-11-30&to=2020-12-04&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2020-11-30..2020-12-04&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2020-11-30..2020-12-04&type=Issues) | [@rkevin-arch](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Arkevin-arch+updated%3A2020-11-30..2020-12-04&type=Issues) | [@snickell](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asnickell+updated%3A2020-11-30..2020-12-04&type=Issues)

### [0.12.2] - 2020-11-30

Security fix for GHSA-384w-5v3f-q499: Deprecated `c.Authenticator.whitelist` configuration was ignored instead of mapped to newer `c.Authenticator.allowed_users` when used with JupyterHub 1.2 and OAuthenticator 0.12.0-0.12.1.

### [0.12.1] - 2020-11-20

#### Bugs fixed

- Avoid appending code, state parameters to `next_url` [#386](https://github.com/jupyterhub/oauthenticator/pull/386) ([@minrk](https://github.com/minrk))

#### Maintenance and upkeep improvements

- Remove support for python 3.5 [#384](https://github.com/jupyterhub/oauthenticator/pull/384) ([@consideRatio](https://github.com/consideRatio))
- migrate from travis to github actions [#383](https://github.com/jupyterhub/oauthenticator/pull/383) ([@minrk](https://github.com/minrk))
- CI: Stop testing py35 and don't test on tagged commits [#379](https://github.com/jupyterhub/oauthenticator/pull/379) ([@consideRatio](https://github.com/consideRatio))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2020-10-26&to=2020-11-18&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2020-10-26..2020-11-18&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2020-10-26..2020-11-18&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2020-10-26..2020-11-18&type=Issues)

### [0.12.0] - 2020-10-26

#### Enhancements made

- [OpenShift] Enable cert verification for self-signed certs and auto-load auth api URL [#363](https://github.com/jupyterhub/oauthenticator/pull/363) ([@vpavlin](https://github.com/vpavlin))
- [Globus] Support custom username handling [#357](https://github.com/jupyterhub/oauthenticator/pull/357) ([@NickolausDS](https://github.com/NickolausDS))
- [Google] Adding refresh_token [#350](https://github.com/jupyterhub/oauthenticator/pull/350) ([@missingcharacter](https://github.com/missingcharacter))
- [Google] Added optional support for google groups [#341](https://github.com/jupyterhub/oauthenticator/pull/341) ([@missingcharacter](https://github.com/missingcharacter))
- [All] Added extra_authorize_params to pass extra params in the initial request to the identity provider [#338](https://github.com/jupyterhub/oauthenticator/pull/338) ([@NickolausDS](https://github.com/NickolausDS))
- [GitLab] Improve subgroup support [#333](https://github.com/jupyterhub/oauthenticator/pull/333) ([@akhmerov](https://github.com/akhmerov))

#### Bugs fixed

- [All] Let auth cookie be influenced by JupyterHub's cookie_options configuration [#378](https://github.com/jupyterhub/oauthenticator/pull/378) ([@Wh1isper](https://github.com/Wh1isper))
- [GitHub] Respect validate_server_cert attribute [#354](https://github.com/jupyterhub/oauthenticator/pull/354) ([@nvs-abhilash](https://github.com/nvs-abhilash))
- [Generic] tls verify not being honored at the httprequest level when internal_ssl is enabled [#326](https://github.com/jupyterhub/oauthenticator/pull/326) ([@sstarcher](https://github.com/sstarcher))

#### Maintenance and upkeep improvements

- Rename OAuthenticator.whitelist to allow [#366](https://github.com/jupyterhub/oauthenticator/pull/366) ([@GeorgianaElena](https://github.com/GeorgianaElena))
- Python package extra dependencies updated [#343](https://github.com/jupyterhub/oauthenticator/pull/343) ([@missingcharacter](https://github.com/missingcharacter))
- [Generic] Fix failing GenericOAuthenticator tests [#339](https://github.com/jupyterhub/oauthenticator/pull/339) ([@GeorgianaElena](https://github.com/GeorgianaElena))
- [Globus] Remove the need for globus_sdk as a python dependency [#337](https://github.com/jupyterhub/oauthenticator/pull/337) ([@NickolausDS](https://github.com/NickolausDS))

#### Documentation improvements

- Add changelog for 0.12.0 release [#377](https://github.com/jupyterhub/oauthenticator/pull/377) ([@consideRatio](https://github.com/consideRatio))
- [Globus] Docs: explain identity_provider better [#362](https://github.com/jupyterhub/oauthenticator/pull/362) ([@NickolausDS](https://github.com/NickolausDS))
- [OpenShift] Docs: fix broken link for OpenShift OAuth service accounts [#352](https://github.com/jupyterhub/oauthenticator/pull/352) ([@nscozzaro](https://github.com/nscozzaro))
- Docs: Updating sphinx and pandas_sphinx_theme references [#345](https://github.com/jupyterhub/oauthenticator/pull/345) ([@missingcharacter](https://github.com/missingcharacter))
- [Google] Added optional support for google groups [#341](https://github.com/jupyterhub/oauthenticator/pull/341) ([@missingcharacter](https://github.com/missingcharacter))
- [Globus] Remove the need for globus_sdk as a python dependency [#337](https://github.com/jupyterhub/oauthenticator/pull/337) ([@NickolausDS](https://github.com/NickolausDS))
- Update docs [#336](https://github.com/jupyterhub/oauthenticator/pull/336) ([@GeorgianaElena](https://github.com/GeorgianaElena))
- [Generic] Usage example for Nextcloud [#268](https://github.com/jupyterhub/oauthenticator/pull/268) ([@arneki](https://github.com/arneki))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2020-01-31&to=2020-10-26&type=c))

[@ablekh](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aablekh+updated%3A2020-01-31..2020-10-26&type=Issues) | [@akhmerov](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aakhmerov+updated%3A2020-01-31..2020-10-26&type=Issues) | [@Analect](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AAnalect+updated%3A2020-01-31..2020-10-26&type=Issues) | [@arneki](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aarneki+updated%3A2020-01-31..2020-10-26&type=Issues) | [@bellackn](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Abellackn+updated%3A2020-01-31..2020-10-26&type=Issues) | [@betatim](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Abetatim+updated%3A2020-01-31..2020-10-26&type=Issues) | [@CJCShadowsan](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ACJCShadowsan+updated%3A2020-01-31..2020-10-26&type=Issues) | [@cmseal](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Acmseal+updated%3A2020-01-31..2020-10-26&type=Issues) | [@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2020-01-31..2020-10-26&type=Issues) | [@d0m84](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ad0m84+updated%3A2020-01-31..2020-10-26&type=Issues) | [@daniel-ciocirlan](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Adaniel-ciocirlan+updated%3A2020-01-31..2020-10-26&type=Issues) | [@dmpe](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Admpe+updated%3A2020-01-31..2020-10-26&type=Issues) | [@dmvieira](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Admvieira+updated%3A2020-01-31..2020-10-26&type=Issues) | [@GeorgianaElena](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AGeorgianaElena+updated%3A2020-01-31..2020-10-26&type=Issues) | [@ghezalsherdil](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aghezalsherdil+updated%3A2020-01-31..2020-10-26&type=Issues) | [@guimou](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aguimou+updated%3A2020-01-31..2020-10-26&type=Issues) | [@gweis](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Agweis+updated%3A2020-01-31..2020-10-26&type=Issues) | [@hardik42](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ahardik42+updated%3A2020-01-31..2020-10-26&type=Issues) | [@hbuttguavus](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ahbuttguavus+updated%3A2020-01-31..2020-10-26&type=Issues) | [@jamescross91](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ajamescross91+updated%3A2020-01-31..2020-10-26&type=Issues) | [@linkcd](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Alinkcd+updated%3A2020-01-31..2020-10-26&type=Issues) | [@louis-she](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Alouis-she+updated%3A2020-01-31..2020-10-26&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2020-01-31..2020-10-26&type=Issues) | [@meeseeksmachine](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ameeseeksmachine+updated%3A2020-01-31..2020-10-26&type=Issues) | [@michec81](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amichec81+updated%3A2020-01-31..2020-10-26&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2020-01-31..2020-10-26&type=Issues) | [@missingcharacter](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amissingcharacter+updated%3A2020-01-31..2020-10-26&type=Issues) | [@mransley](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amransley+updated%3A2020-01-31..2020-10-26&type=Issues) | [@NickolausDS](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ANickolausDS+updated%3A2020-01-31..2020-10-26&type=Issues) | [@nscozzaro](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Anscozzaro+updated%3A2020-01-31..2020-10-26&type=Issues) | [@nvs-abhilash](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Anvs-abhilash+updated%3A2020-01-31..2020-10-26&type=Issues) | [@patback66](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Apatback66+updated%3A2020-01-31..2020-10-26&type=Issues) | [@PaulMazzuca](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3APaulMazzuca+updated%3A2020-01-31..2020-10-26&type=Issues) | [@RAbraham](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ARAbraham+updated%3A2020-01-31..2020-10-26&type=Issues) | [@sampathkethineedi](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asampathkethineedi+updated%3A2020-01-31..2020-10-26&type=Issues) | [@saurav-bhagat](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asaurav-bhagat+updated%3A2020-01-31..2020-10-26&type=Issues) | [@shivan10](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ashivan10+updated%3A2020-01-31..2020-10-26&type=Issues) | [@SolarisYan](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ASolarisYan+updated%3A2020-01-31..2020-10-26&type=Issues) | [@sstarcher](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asstarcher+updated%3A2020-01-31..2020-10-26&type=Issues) | [@support](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Asupport+updated%3A2020-01-31..2020-10-26&type=Issues) | [@umar-sik](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aumar-sik+updated%3A2020-01-31..2020-10-26&type=Issues) | [@vpavlin](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Avpavlin+updated%3A2020-01-31..2020-10-26&type=Issues) | [@welcome](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Awelcome+updated%3A2020-01-31..2020-10-26&type=Issues) | [@Wh1isper](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AWh1isper+updated%3A2020-01-31..2020-10-26&type=Issues) | [@willingc](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Awillingc+updated%3A2020-01-31..2020-10-26&type=Issues) | [@yuvipanda](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Ayuvipanda+updated%3A2020-01-31..2020-10-26&type=Issues) | [@zhiyuli](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Azhiyuli+updated%3A2020-01-31..2020-10-26&type=Issues)

## 0.11

### [0.11.0] - 2020-01-30

The main change in 0.11 is a refactoring of classes to remove mixins,
reducing the amount of boilerplate needed.
In addition, there are some fixes to the Azure AD Authenticator.
This should be a fully backward-compatible change,
except in cases where some subclasses were importing these now-unneeded mixin classes,
such as GitHubLoginHandler, GitHubMixin, etc.

All options should now be configurable via the standard jupyterhub config file.
There should no longer be any options that are _only_ configurable via environment variable.

This release also _removes_ the latest Authenticators added in 0.10
(AzureAdB2COAuthenticator, AWSCognitoOAuthenticator, YandexOAuthenticator),
which were released without being fully supported and
which can be achieved through configuration of existing classes,
such as `AzureAd` and `Generic`.

We don't plan to accept further contributions of new providers if they can be achieved through customization or configuration of existing classes.
Rather, contributors are encouraged to provide example documentation for using new providers,
or pull requests addressing gaps necessary to do so with the GenericOAuthenticator.

([full changelog](https://github.com/jupyterhub/oauthenticator/compare/0.10.0...ae199077a3a580cb849af17ceccfe8e498134ea3))

#### Merged PRs

- [AzureAD] Don't pass resource when requesting a token [#328](https://github.com/jupyterhub/oauthenticator/pull/328) ([@craigminihan](https://github.com/craigminihan))
- Remove mixins, per-Authenticator LoginHandler classes [#323](https://github.com/jupyterhub/oauthenticator/pull/323) ([@minrk](https://github.com/minrk))
- [AzureAD] Add support for setting login_service [#319](https://github.com/jupyterhub/oauthenticator/pull/319) ([@zevaryx](https://github.com/zevaryx))
- skeleton of sphinx docs [#316](https://github.com/jupyterhub/oauthenticator/pull/316) ([@minrk](https://github.com/minrk))

#### Contributors to this release

([GitHub contributors page for this release](https://github.com/jupyterhub/oauthenticator/graphs/contributors?from=2019-11-27&to=2020-01-30&type=c))

[@consideRatio](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3AconsideRatio+updated%3A2019-11-27..2020-01-30&type=Issues) | [@craigminihan](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Acraigminihan+updated%3A2019-11-27..2020-01-30&type=Issues) | [@Dmitry1987](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ADmitry1987+updated%3A2019-11-27..2020-01-30&type=Issues) | [@manics](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Amanics+updated%3A2019-11-27..2020-01-30&type=Issues) | [@minrk](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Aminrk+updated%3A2019-11-27..2020-01-30&type=Issues) | [@NickolausDS](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3ANickolausDS+updated%3A2019-11-27..2020-01-30&type=Issues) | [@zevaryx](https://github.com/search?q=repo%3Ajupyterhub%2Foauthenticator+involves%3Azevaryx+updated%3A2019-11-27..2020-01-30&type=Issues)

## 0.10

### [0.10.0] - 2019-11-27

#### New

- Add AzureAdB2COAuthenticator [#307](https://github.com/jupyterhub/oauthenticator/pull/307) ([@linkcd](https://github.com/linkcd))
- Add support for `GenericOAuthenticator.username_key` to hold a callable value [#305](https://github.com/jupyterhub/oauthenticator/pull/305) ([@eslavich](https://github.com/eslavich))
- Add `AzureAdOAuthenticator.username_claim` config field [#280](https://github.com/jupyterhub/oauthenticator/pull/280) ([@jeff-sternberg](https://github.com/jeff-sternberg))
- Add `AWSCognitoAuthenticator` [#269](https://github.com/jupyterhub/oauthenticator/pull/269) ([@jmartinc89](https://github.com/jmartinc89))

#### Fixed

- mediawiki: utf-8 > binary strings, req. mwoauth>=0.3.7 [#297](https://github.com/jupyterhub/oauthenticator/pull/297) ([@consideRatio](https://github.com/consideRatio))
- Fixed Globus Logout Handler, added test [#288](https://github.com/jupyterhub/oauthenticator/pull/288) ([@NickolausDS](https://github.com/NickolausDS))
- Include inherited members in GitLab auth checks, requires GitLab 12.4 or newer, but will fall back to previous behavior for older GitLab versions. [#283](https://github.com/jupyterhub/oauthenticator/pull/283) ([@vindvaki](https://github.com/vindvaki))

#### Maintenance

- Fixed content index in readme, and fixed typo in comments [#310](https://github.com/jupyterhub/oauthenticator/pull/310) ([@linkcd](https://github.com/linkcd))
- Add scopes documentation to auth0 example [#303](https://github.com/jupyterhub/oauthenticator/pull/303) ([@jbradenbrown](https://github.com/jbradenbrown))
- Add py3.8 for CI testing [#302](https://github.com/jupyterhub/oauthenticator/pull/302) ([@consideRatio](https://github.com/consideRatio))
- Travis: Deploy releases to pypi [#301](https://github.com/jupyterhub/oauthenticator/pull/301) ([@manics](https://github.com/manics))
- Disable MediaWiki's mwoauth==0.3.5 due to a regression [#295](https://github.com/jupyterhub/oauthenticator/pull/295) ([@consideRatio](https://github.com/consideRatio))
- Add RELEASE.md [#294](https://github.com/jupyterhub/oauthenticator/pull/294) ([@consideRatio](https://github.com/consideRatio))
- Add PyPI/Travis build badges to README.md [#293](https://github.com/jupyterhub/oauthenticator/pull/293) ([@consideRatio](https://github.com/consideRatio))
- Fix project name typo [#292](https://github.com/jupyterhub/oauthenticator/pull/292) ([@kinow](https://github.com/kinow))
- Use traitlet.default for Azure AD tenant_id [#282](https://github.com/jupyterhub/oauthenticator/pull/282) ([@jeff-sternberg](https://github.com/jeff-sternberg))
- Add clarifying comment into README code block [#279](https://github.com/jupyterhub/oauthenticator/pull/279) ([@raethlein](https://github.com/raethlein))

## 0.9

### [0.9.0] - 2019-07-30

- switch to asyncio coroutines from tornado coroutines (requires Python 3.5)
- add `GenericOAuthenticator.userdata_token_method` configurable
- add `GenericOAuthenticator.basic_auth` configurable
- support for OpenShift 4.0 API changes

## 0.8

### [0.8.2] - 2019-04-16

- Validate login URL redirects to avoid Open Redirect issues.

### [0.8.1] - 2019-02-28

- Provide better error messages
- Allow auth scope to be array or strings
- `GitHubOAuthenticator`: More efficient `org_whitelist` check
- Use pytest-asyncio instead of pytest-tornado
- CILogon: New additional_username_claims config for linked identities, fallback to the primary username claim
- `GitLabOAuthenticator`: New `project_id_whitelist` config to whitelist users who have Developer+ access to the project
- `GoogleOAuthenticator`: Allow email domains (`hosted_domain`) to be a list
- Add `jupyterhub-authenticator` entrypoints for jupyterhub 1.0.
- Cleanup & bugfixes

### [0.8.0] - 2018-08-10

- Add `azuread.AzureADOAuthenticator`
- Add `CILogonOAuthenticator.idp_whitelist` and `CILogonOAuthenticator.strip_idp_domain` options
- Add `GenericOAuthenticator.tls_verify` and `GenericOAuthenticator.extra_params` options
- Add refresh token and scope to generic oauthenticator auth state
- Better error messages when GitHub oauth fails
- Stop normalizing mediawiki usernames, which can be case-sensitive
- Fixes for group-membership checks with GitLab
- Bugfixes in various authenticators
- Deprecate GITLAB_HOST in favor of GITLAB_URL, since we expect `https://` in the url, not just the host.

## 0.7

### [0.7.3] - 2018-02-16

0.7.3 is a security fix for CVE-2018-7206.
It fixes handling of `gitlab_group_whitelist` when using GitLabOAuthenticator.
The same fix is backported to 0.6.2.

### [0.7.2] - 2017-10-27

- Fix CILogon OAuth 2 implementation. ePPN claim is used for default username
  (typically institutional email).
  `CILogonOAuthenticator.username_claim` can be used to change which field is
  used for JupyterHub usernames.
- `GenericOAuthenticator.login_service` is now configurable.
- default to GitLab API version 4 and allow v3 via GITLAB_API_VERSION=3 environment variable.
- Add `GlobusOAuthenticator.revoke_tokens_on_logout` and
  `GlobusOAuthenticator.logout_redirect_url` config for further clearing
  of credentials on JupyterHub logout.

### [0.7.1] - 2017-10-04

- fix regression in 0.7.0 preventing authentication via providers other than GitHub, MediaWiki

### [0.7.0] - 2017-10-02

0.7.0 adds significant new functionality to all authenticators.

- CILogon now uses OAuth 2 instead of OAuth 1, to be more consistent with the rest.
- All OAuthenticators support `auth_state` when used with JupyterHub 0.8.
  In every case, the auth_state is a dict with two keys: `access_token` and the
  user-info reply identifying the user.
  For instance, GitHubOAuthenticator auth_state looks like:

  ```python
  {
    'acces_token': 'abc123',
    'github_user': {
      'username': 'fake-user',
      'email': 'fake@email.com',
      ...
    }
  }
  ```

  auth_state can be passed to Spawners by defining a `.pre_spawn_start` method.
  See examples/auth_state for an example.

- All OAuthenticators have a `.scope` trait, which is a list of string scopes to request.
  See your OAuth provider's documentation for what scopes you may want.
  This is useful in conjunction with `auth_state`, which may be used to pass access tokens
  to Spawners via environment variables. `.scope` can control what permissions those
  tokens will have. In general, OAuthenticator default scopes should only have read-only access to identify users.
- GITHUB_HTTP environment variable can be used to talk to HTTP-only GitHub Enterprise deployments.

## 0.6

### [0.6.2] - 2018-02-16

0.6.2 is a security fix for CVE-2018-7206.
It fixes handling of `gitlab_group_whitelist` when using GitLabOAuthenticator.

### [0.6.1] - 2017-08-11

0.6.1 has bugfixes for new behaviors in 0.6.0

- Use `.login_url` and `next_url` from JupyterHub if defined (JupyterHub 0.8)
- Fix empty login_url where final login redirect could be omitted
- Fix mediawiki authenticator, which broke in 0.6.0
- Encode state as base64 instead of JSON, for easier passing in URLs

### [0.6.0] - 2017-07-25

- Support for changes in upcoming JupyterHub 0.8
- Refactor to share more code across providers
- Deprecated GITHUB_CLIENT_ID and other provider-specific environment variables
  for common options.
  All OAuthenticators support the same OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, and OAUTH_CALLBACK_URL environment variables.
- New authenticators:
  - auth0
  - globus
  - okpy
  - openshift
  - generic - a generic implementation that can work with any OAuth2 provider

## 0.5

### [0.5.1] - 2016-10-05

- Fixes in BitbucketOAuthenticator.check_whitelist

### [0.5.0] - 2016-09-02

- Add GitLabOAuthenticator

## 0.4

### [0.4.1] - 2016-05-18

- Fix typo preventing Google OAuth from working in 0.4.0

### [0.4.0] - 2016-05-11

- Enable username normalization (for mixed-case names on GitHub, requires JupyterHub 0.5).
  This removes `GitHubOAuthenticator.username_map` introduced in 0.3,
  because the oauth2 Authenticator has `.username_map` as of 0.5.

## [0.3] - 2016-04-20

- Add Google authenticator
- Allow specifying OAuth scope
- Add `GitHubOAuthenticator.username_map` for mapping GitHub usernames to system usernames.

## [0.2] - 2016-01-04

- Add mediawiki authenticator

## 0.1 - 2015-12-22

- First release

[unreleased]: https://github.com/jupyterhub/oauthenticator/compare/14.2.0...HEAD
[14.2.0]: https://github.com/jupyterhub/oauthenticator/compare/14.1.0...14.2.0
[14.1.0]: https://github.com/jupyterhub/oauthenticator/compare/14.0.0...14.1.0
[14.0.0]: https://github.com/jupyterhub/oauthenticator/compare/0.13.0...14.0.0
[0.13.0]: https://github.com/jupyterhub/oauthenticator/compare/0.12.2...0.13.0
[0.12.2]: https://github.com/jupyterhub/oauthenticator/compare/0.12.1...0.12.2
[0.12.1]: https://github.com/jupyterhub/oauthenticator/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/jupyterhub/oauthenticator/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/jupyterhub/oauthenticator/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/jupyterhub/oauthenticator/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/jupyterhub/oauthenticator/compare/0.8.2...0.9.0
[0.8.2]: https://github.com/jupyterhub/oauthenticator/compare/0.8.1...0.8.2
[0.8.1]: https://github.com/jupyterhub/oauthenticator/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/jupyterhub/oauthenticator/compare/0.7.3...0.8.0
[0.7.3]: https://github.com/jupyterhub/oauthenticator/compare/0.7.2...0.7.3
[0.7.2]: https://github.com/jupyterhub/oauthenticator/compare/0.7.1...0.7.2
[0.7.1]: https://github.com/jupyterhub/oauthenticator/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/jupyterhub/oauthenticator/compare/0.6.1...0.7.0
[0.6.2]: https://github.com/jupyterhub/oauthenticator/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/jupyterhub/oauthenticator/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/jupyterhub/oauthenticator/compare/0.5.1...0.6.0
[0.5.1]: https://github.com/jupyterhub/oauthenticator/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/jupyterhub/oauthenticator/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/jupyterhub/oauthenticator/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/jupyterhub/oauthenticator/compare/0.3.0...0.4.0
[0.3]: https://github.com/jupyterhub/oauthenticator/compare/0.2.0...0.3.0
[0.2]: https://github.com/jupyterhub/oauthenticator/compare/0.1.0...0.2.0
