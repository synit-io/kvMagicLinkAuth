# Development

This package is maintained by [synit.io](https://www.synit.io) and is intended
to stay fully compatible with modern Deno and JSR publishing requirements.

## Local workflow

Install dependencies and run the standard quality gates:

```bash
deno task check
deno task browser:install
deno task test:browser
deno task e2e
```

Run the fast unit and documentation checks separately with:

```bash
deno task test
deno task test:docs
```

`deno task e2e` requires Docker with Docker Compose. It starts Mailpit and a
containerized Deno test app, executes the E2E suite against the running stack,
and removes the containers afterward.

`deno task check` runs formatting, lint, unit/security/cookie tests, and
extracted README example tests. The example tests typecheck all five
authentication and authorization examples and execute their login handlers with
isolated KV and mail fixtures. They require permission to launch `deno`
subprocesses.

`deno task test:browser` runs Chromium against an isolated local HTTP fixture.
It checks browser cookie acceptance, cross-site email navigation, binding on a
changed IP, the authenticated redirect, and cookie clearing. Install the
matching browser with `deno task browser:install`; Linux CI also passes
`--with-deps`. `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` can select an existing
Chromium executable. The test uses a temporary browser context and does not
access a personal profile.

Browser installation requires Deno 2.9.6 or newer; older releases lack the Node
HTTP lookup support used by Playwright's downloader. CI uses Deno 2.9.6 for
browser and E2E tests while retaining Deno 2.7.11 for unit and documentation
compatibility checks.

The browser task uses full Deno permissions for Playwright's Linux `/proc`
checks and browser subprocess management. Unit and documentation tasks retain
their narrower permissions.

E2E HTTP ports are bound to `127.0.0.1`; SMTP stays inside the Compose network.
The E2E app uses the socket peer address rather than forwarding headers, and its
tests verify that a forged header cannot evade an IP block. Its detailed JSON
responses are test fixtures, not the public response contract shown in README.

## GitHub automation

The repository includes four automation files under `.github`:

- `.github/workflows/ci-main.yml` runs `deno task check`, `deno task e2e`, and
  `deno task test:browser` on pull requests targeting `main`, on every push to
  `main` (including merges), and on manual dispatch. The E2E checkout path
  includes spaces and Unicode to exercise filesystem URL conversion.
- `.github/workflows/deno-deps-update.yml` runs every Monday at 05:00 UTC and
  opens a PR with `deno outdated --update --latest` changes only after the
  `deno task check` gate passes.
- `.github/workflows/cleanup-deno-dependency-branches.yml` runs when a
  `chore/deno-dependencies*` pull request is merged into `main` and deletes
  orphaned dependency-update branches that are no longer used by open PRs.
- `.github/dependabot.yml` keeps GitHub Actions and Docker dependencies updated.
  Dependabot does not currently provide a dedicated Deno/JSR ecosystem updater,
  so Deno dependency updates are handled by the scheduled workflow above.

## Why tests need file permissions

The original unit suite opens an isolated local Deno KV database file per test;
the additional security tests use in-memory KV. Documentation tests create and
remove temporary TypeScript fixtures. That is why `--unstable-kv`,
`--allow-read`, and `--allow-write` are required for `deno test`.

## Release checklist

1. Update public API docs in `README.md` when behavior changes.
2. Add the release notes to `CHANGELOG.md`.
3. Run `deno task check`.
4. Run `deno task e2e`.
5. Run `deno task browser:install` and `deno task test:browser`.
6. Run `deno publish --dry-run` to validate JSR package contents.
7. Publish the package with `deno publish` once the dry run is clean.

## Design notes

- Keep the public API small and explicit.
- Prefer readable control flow over clever abstractions.
- Treat redirect handling, token validation, and cookie serialization as
  security-sensitive areas.
- Keep package docs current with the published API surface.
