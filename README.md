
🎭 Extract Microsoft OAuth tokens using Playwright browser automation.

## 📦 Installation

To install `msauth-browser`, you can use `pip`, `pip3` or `pipx`. Either from `pypi` repository or from `GitHub` source. Prefer using [`pipx`](https://pypa.github.io/pipx/), since it install Python applications in isolated virtual environments.

### From [PyPI](https://pypi.org/project/msauth-browser/)

```bash
pipx install msauth-browser
```

```bash
pip install msauth-browser
```

### From GitHub

```bash
pip install "git+https://github.com/n3rada/msauth-browser"
```

```bash
pipx install "git+https://github.com/n3rada/msauth-browser"
```

### Playwright

Ensure chromium playwright browser is available:
```shell
playwright install chromium
```

If installed with `pipx`:

- Windows PowerShell
```powershell
& "$(pipx environment --value PIPX_LOCAL_VENVS)\msauth-browser\Scripts\playwright.exe" install chromium
```

If you are in a corporate environment with TLS inspection (e.g., using Zscaler):
```powershell
$env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
```

## Usage

```shell
msauth-browser
```

Or, to have the right to send emails through Microsoft Graph API:

```shell
msauth-browser --add-scope "https://graph.microsoft.com/Mail.Send"
```

### Options:
- `--add-scope <scope>`: Add OpenID Connect (OIDC) scopes.
- `--prt-cookie <JWT>`: Use an `x-ms-RefreshTokenCredential` PRT cookie for SSO-based login.
- `--headless`: Run Playwright in headless mode.

```shell
msauth-browser --headless --prt-cookie "<x-ms-RefreshTokenCredential>"
```

## About the PRT Cookie

The PRT cookie is officially `x-ms-RefreshTokenCredential` and it is a JSON Web Token (JWT). The actual Primary Refresh Token (PRT) is encapsulated within the `refresh_token`, which is encrypted by a key under the control of Entra ID, rendering its contents opaque. 

It can be used as a cookie wired to `login.microsoftonline.com` domain in order to use-it to authenticate to the service while skiping credential prompts.

## Microsoft first-party apps

Microsoft first-party apps have hardcoded, pre-approved scopes.

You cannot simply add `ChannelMessage.Read.All` to the scope parameter of the Teams application, the request will fail.

## Why not [microsoft-authentication-library-for-python](https://github.com/AzureAD/microsoft-authentication-library-for-python) (MSAL)?

One major limitation is that it [requires localhost](https://msal-python.readthedocs.io/en/latest/) redirect URIs.

![MSAL documentation indicating localhost requirement](https://github.com/n3rada/msauth-browser/blob/main/media/msal_documentation.png)

It also does not support integrating PRT cookies.

## Adding new app presets

1. Drop a JSON file into [`msauth_browser/configs/`](./src/msauth_browser/configs/).
2. Provide the required fields:
	- `name`
	- `client_id`
	- `redirect_uri`
	- `default_scopes` (array of scopes) — optional; if omitted or empty, the tool defaults to `openid` and `offline_access`.
3. Optionally include a `slug` field; otherwise the filename (without extension) becomes the lookup key.
