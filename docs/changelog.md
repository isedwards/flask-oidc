# Changelog


## 2.1.1 (2023-10-27)

### Fixed

- Avoid redirect loops when the app is not mounted on the webserver root (#52)

### Changed

- Use REUSE for licences
- Convert the changelog to markdown

### Added

- Publish to PyPI and Github when a tag is pushed


## 2.1.0 (2023-10-09)

### Fixed

- Handle token expiration when there is no `refresh_token` or no token URL (#39)

### Changed

- Restore the `OVERWRITE_REDIRECT_URI` configuration option as
  `OIDC_OVERWRITE_REDIRECT_URI`.
- The `redirect_uri` that is generated and sent to the ID provider is no longer
  forced to HTTPS, because the
  [the OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
  is actually only a strong recommendation (#35). You can
  use `OVERWRITE_REDIRECT_URI` if you want to force it to HTTPS (or any other
  URL).


## 2.0.3 (2023-09-08)

### Fixed

- Use the `OIDC_CALLBACK_ROUTE` with the ID provider when it is defined,
  instead of the default (#21)
- Auto-renew tokens when they have expired (if possible), as version 1.x used
  to do (#19)

### Changed

- The `redirect_uri` that is generated and sent to the ID provider is always
  HTTPS, as [the OIDC spec](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
  mandates.
- Don't request the `profile` scope by default, as version 1.x used to do
  (#21).


## 2.0.2 (2023-08-23)

### Fixed

- Avoid a redirect loop on logout when the token is expired (#17).


### Deprecated

- Configuration option `OIDC_USERINFO_URL` (and the `userinfo_uri` key in
  `client_secrets`) (#15).


## 2.0.1 (2023-08-22)

This is a bugfix release.

### Fixed

- Don't crash if the `client_secrets` don't contain a `userinfo_uri` key (#13).
- Handle older versions of Werkzeug.


## 2.0.0 (2023-08-21)

This is a major release that rebases the Flask OIDC API on
[Authlib](https://authlib.org/).

### Removed

- Custom callback with the `OpenIDConnect.custom_callback()` decorator
- Registration has been moved to the
  [oidc-register package](https://pypi.org/project/oidc-register/)
- Configuration option `OIDC_GOOGLE_APPS_DOMAIN`
- Configuration option `OIDC_VALID_ISSUERS`
- Configuration option `OIDC_REQUIRE_VERIFIED_EMAIL`
- Configuration option `OIDC_RESOURCE_CHECK_AUD`
- The following parameters of the `OpenIDConnect` constructor have been
  removed:

  - `credentials_store`
  - `http`
  - `time`
  - `urandom`

### Deprecated

- Configuration option `OIDC_OPENID_REALM`
- Configuration option `OIDC_CALLBACK_ROUTE`
- Configuration option `OVERWRITE_REDIRECT_URI`
- The following configuration options have been removed because the
  functionality is now handled by Authlib:

  - `OIDC_ID_TOKEN_COOKIE_NAME`
  - `OIDC_ID_TOKEN_COOKIE_PATH`
  - `OIDC_ID_TOKEN_COOKIE_TTL`
  - `OIDC_COOKIE_SECURE`

- The `OpenIDConnect.user_getinfo()` and `OpenIDConnect.user_getfield()`
  methods are deprecated, you'll find all the user information in the
  session: `session["oidc_auth_profile"]`.
  If you need to get the user information using a specific token, you can
  do so by calling `g._oidc_auth.userinfo(token=token)`.
- The `OpenIDConnect.logout()` method is deprecated, just redirect to the
  `/logout` view.

### Changed

The callback route (aka "redirect URL") is not configurable with
`OIDC_CALLBACK_ROUTE` anymore. It is always `/authorize`, but a prefix can
be configured when instanciating the `OpenIDConnect` extension (or calling
its `OpenIDConnect.init_app()` method:

```python
    app = Flask(__name__)
    openid = OpenIDConnect(app, prefix="/oidc")
    # The OIDC redirect URL will be /oidc/authorize
```

This will also give you `/login` and `/logout` views, prefixed identically.

The `OIDC_SCOPES` configuration value should now be a string, where the
scopes are separated with spaces.

The minimum Python version is `3.8`.

### Added

The `OpenIDConnect.accept_token()` decorator now accepts a `scopes` parameter,
which is a list of scopes that the provided token must include for the view to
be authorized. It is an Authlib
[ResourceProtector](https://docs.authlib.org/en/latest/flask/2/resource-server.html).

The Authlib app is available in the `g._oidc_auth` variable. This means that
there cannot be more than one `OpenIDConnect` extension on a given Flask
application. If you need more, we advise you to use Authlib directly.

### Development

- A [pre-commit](https://pre-commit.com/) config has been added, please enable
  it with `pre-commit install`
- Unit tests are run by [Tox](https://tox.readthedocs.io/)
- A coverage report is produced, and the coverage must be 100%
- The git submodule for documentation themes has been dropped
- The code is formatted using [Black](https://black.readthedocs.io/)
- The code is linted using [Ruff](https://ruff.rs)
- The package metadata is managed by [Poetry](https://python-poetry.org/)
- CI is run using Github Actions, Travis config has been dropped
- Dependencies are updated using [Renovate](https://docs.renovatebot.com/)
