# Code signing

`riff.exe` is currently shipped **unsigned**, so Windows SmartScreen warns on
first run. For a tool that installs a certificate authority and decrypts TLS,
that is a bad look as well as a real friction point.

[SignPath Foundation](https://signpath.org/) issues free code signing
certificates to open-source projects, keeps the private key on an HSM, and
verifies that the binary was built from the project's public repository. That
last part matters more than the warning dialog: it ties the released binary to
this source tree, which is exactly the provenance question a security reviewer
asks.

`.github/workflows/release.yml` is already wired for it. Until the application
is approved, the workflow builds and attaches an unsigned binary; it starts
signing automatically once the secrets exist.

## Applying

1. Apply at <https://signpath.org/apply>. riff qualifies: public repository,
   OSI-approved licence (MIT), and a real user-facing tool.

   Useful things to have ready:

   | | |
   |---|---|
   | Project | riff |
   | Repository | `https://github.com/yamazed/riff` |
   | Licence | MIT |
   | What it is | A scriptable HTTP(S) interception proxy with a rule language, a live web UI, an API client and a vulnerability scanner. |
   | Build | GitHub Actions, `.github/workflows/release.yml`, PyInstaller one-file |
   | Artifact | a single `riff.exe` |

   Expect them to ask about the interception and scanning features. Answer
   plainly: the CA is generated per machine and never shipped, it can be
   name-constrained (`riff ca regenerate --constrain-to ...`), the active
   scanner refuses to run without an explicit host scope, and `demo/app.py` is
   deliberately vulnerable but binds loopback only.

2. When approved, SignPath gives you an organization ID, a project slug, a
   signing policy and an artifact configuration.

3. Add to the repository — **Settings → Secrets and variables → Actions**:

   Secrets:
   - `SIGNPATH_API_TOKEN`
   - `SIGNPATH_ORGANIZATION_ID`

   Variables:
   - `SIGNPATH_PROJECT_SLUG` (e.g. `riff`)
   - `SIGNPATH_SIGNING_POLICY` (e.g. `release-signing`)
   - `SIGNPATH_ARTIFACT_CONFIG` (e.g. `initial`)

4. Publish a release, or run the **Release** workflow by hand against an
   existing tag. The log says whether it attached a signed or unsigned binary.

## Verifying a signature

```powershell
Get-AuthenticodeSignature .\riff.exe | Format-List Status, SignerCertificate
```

`Status` should be `Valid`.

## The alternatives, for the record

| | Cost | Notes |
|---|---|---|
| **SignPath Foundation** | free | OSS only; key on their HSM; verifies the build came from this repo |
| Azure Artifact Signing | quote-based | Microsoft-run; needs identity validation |
| Traditional OV/EV certificate | ~$200–700/yr | Plus a hardware token — mandatory for code signing keys since June 2023 |

A self-signed Authenticode certificate is not worth doing: it satisfies nobody
and still trips SmartScreen.
