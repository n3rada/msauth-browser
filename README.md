# 🎭 msauth-browser

Extract Microsoft OAuth tokens using [Playwright](https://playwright.dev/python/) browser automation.

Microsoft Graph API requires a valid OAuth access token to perform delegated actions like sending emails, reading mailboxes, or enumerating users. Getting that token programmatically is surprisingly painful: MSAL requires localhost redirect URIs, and pure API flows cannot handle MFA prompts, Conditional Access policies, or CAPTCHAs.

`msauth-browser` solves this by driving a real Chromium browser through the full [OAuth 2.0 authorization code flow with PKCE](https://datatracker.ietf.org/doc/html/rfc7636). It handles any interactive challenge exactly as a legitimate user would, and gives you back a ready-to-use access token (and refresh token) that you can feed into your scripts and tooling.

> [!TIP]
> Pair with [ROADtools](https://github.com/dirkjanm/ROADtools) or [GraphSpy](https://github.com/RedByte1337/GraphSpy) for downstream enumeration and exploitation using the acquired tokens.

## 🎯 Why This Tool?

- **Real browser, real auth**: navigates MFA, Conditional Access, device compliance checks, and CAPTCHAs that API-only tools cannot handle.
- **No localhost redirect required**: unlike MSAL, works with any redirect URI, including first-party Microsoft app URIs.
- **First-party app presets**: authenticate as Graph Explorer, Teams, Outlook, etc. to leverage their pre-approved scopes.
- **PRT cookie injection**: inject an `x-ms-RefreshTokenCredential` cookie for SSO-based login, bypassing credential prompts entirely.
- **ROADtools integration**: save tokens in `.roadtools_auth` format for downstream use with [ROADtools](https://github.com/dirkjanm/ROADtools) or [GraphSpy](https://github.com/RedByte1337/GraphSpy), with optional auto-refresh.

## 📦 Installation

Prefer using [`uv`](https://docs.astral.sh/uv/), a fast Python package manager that installs tools in isolated environments. Alternatively, [`pipx`](https://pypa.github.io/pipx/) or `pip` work as well.

### With [uv](https://docs.astral.sh/uv/) (recommended)

[`uv tool install`](https://docs.astral.sh/uv/guides/tools/#installing-tools) persistently installs the tool and adds it to your `PATH`:

**From [PyPI](https://pypi.org/project/msauth-browser/):**

```bash
uv tool install msauth-browser
```

**From GitHub (latest):**

```bash
uv tool install git+https://github.com/n3rada/msauth-browser.git
```

To upgrade later:

```bash
uv tool upgrade msauth-browser
```

> [!TIP]
> You can also run it **without installing** using [`uvx`](https://docs.astral.sh/uv/guides/tools/#running-tools):
> ```bash
> uvx msauth-browser --help
> uvx --from git+https://github.com/n3rada/msauth-browser.git msauth-browser --help
> ```

### With pipx or pip

```bash
pipx install msauth-browser
# or from GitHub
pipx install "git+https://github.com/n3rada/msauth-browser"
```

```bash
pip install msauth-browser
# or from GitHub
pip install "git+https://github.com/n3rada/msauth-browser"
```

### 🎭 Playwright

Ensure the Chromium browser is available:

```shell
playwright install chromium
```

If installed with `uv tool install`:

```shell
uv tool run --from msauth-browser playwright install chromium
```

If installed with `pipx`:

```powershell
& "$(pipx environment --value PIPX_LOCAL_VENVS)\msauth-browser\Scripts\playwright.exe" install chromium
```

If you are in a corporate environment with TLS inspection (e.g., using Zscaler), disable certificate verification first:
```powershell
$env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
```

## 🧸 Usage

```shell
msauth-browser [config] [options]
```

The default configuration is `graph` (Graph Explorer). Available presets:

| Preset | Application |
|--------|-------------|
| `graph` | Graph Explorer |
| `outlook` | Outlook |
| `teams` | Microsoft Teams |
| `powerapps` | Power Apps |
| `powerautomate` | Power Automate |

### 📋 Examples

```shell
# Default: authenticate as Graph Explorer
msauth-browser

# Authenticate as Microsoft Teams
msauth-browser teams

# Request additional Mail.Send scope on Graph Explorer
msauth-browser --add-scope "https://graph.microsoft.com/Mail.Send"

# Use a PRT cookie for SSO (headless, no visible browser)
msauth-browser --headless --prt-cookie "<x-ms-RefreshTokenCredential>"

# Save tokens in ROADtools format with auto-refresh
msauth-browser --save roadtools --refresh
```

### ⚙️ Options

| Flag | Description |
|------|-------------|
| `--add-scope <scope>` | Additional OIDC scope(s) to request |
| `--prt-cookie <JWT>` | `x-ms-RefreshTokenCredential` PRT cookie for SSO |
| `--headless` | Run the browser in headless mode |
| `--save [roadtools]` | Persist tokens (currently supports `roadtools` format) |
| `--refresh` | Auto-refresh the access token before expiry (requires `--save`) |
| `--log-level <LEVEL>` | Set log verbosity (`TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `-V`, `--version` | Show version and exit |

## 🔑 About the PRT Cookie

The PRT cookie is officially `x-ms-RefreshTokenCredential` and it is a JSON Web Token (JWT). The actual Primary Refresh Token (PRT) is encapsulated within the `refresh_token` field, which is encrypted by a key under the control of Entra ID, rendering its contents opaque.

It can be used as a cookie wired to `login.microsoftonline.com` to authenticate and skip credential prompts entirely.

## 🏢 Microsoft First-Party Apps

Microsoft first-party apps have hardcoded, pre-approved scopes.

You cannot simply add `ChannelMessage.Read.All` to the scope parameter of the Teams application, the request will fail. Use `--add-scope` only with scopes that are valid for the selected app configuration.

## ❓ Why Not [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python)?

One major limitation is that MSAL [requires localhost](https://msal-python.readthedocs.io/en/latest/) redirect URIs.

![MSAL documentation indicating localhost requirement](https://github.com/n3rada/msauth-browser/blob/main/media/msal_documentation.png)

It also does not support injecting PRT cookies into the authentication flow.

## 🧩 Adding New App Presets

1. Drop a JSON file into [`msauth_browser/configs/`](./src/msauth_browser/configs/).
2. Provide the required fields:
	- `name`
	- `client_id`
	- `redirect_uri`
	- `default_scopes` (array of scopes), optional; if omitted or empty, defaults to `openid` and `offline_access`.
3. Optionally include a `slug` field; otherwise the filename (without extension) becomes the lookup key.

## 🤝 Contributing

Contributions are welcome and appreciated! Whether it is fixing bugs, adding new app presets, improving the documentation, or sharing feedback, your effort is valued and makes a difference.

Open-source thrives on collaboration and recognition. Contributions, large or small, help improve the tool and its community. Your time and effort are truly valued.

## 🙏 Acknowledgments

- Browser automation powered by [Playwright](https://playwright.dev/python/).
- PKCE flow handled by [pkce](https://github.com/xzava/pkce).
- Token persistence format compatible with [ROADtools](https://github.com/dirkjanm/ROADtools) by [@_dirkjan](https://twitter.com/_dirkjan).
- Logging powered by [Loguru](https://github.com/Delgan/loguru).

## ⚠️ Disclaimer

**This tool is provided strictly for defensive security research, education, and authorized penetration testing.** You must have **explicit written authorization** before running this software against any system you do not own.

This tool is designed for educational purposes only and is intended to assist security professionals in understanding and testing the security of Microsoft Entra ID environments in authorized engagements.

Acceptable environments include:
- Private lab environments you control (local VMs, isolated networks).
- Sanctioned learning platforms (CTFs, Hack The Box, OffSec exam scenarios).
- Formal penetration-test or red-team engagements with documented customer consent.

Misuse of this project may result in legal action.

## ⚖️ Legal Notice

Any unauthorized use of this tool in real-world environments or against systems without explicit permission from the system owner is strictly prohibited and may violate legal and ethical standards. The creators and contributors of this tool are not responsible for any misuse or damage caused.

Use responsibly and ethically. Always respect the law and obtain proper authorization.
