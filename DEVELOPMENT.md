# Development

This package is maintained by [synit.io](https://www.synit.io) and is intended
to stay fully compatible with modern Deno and JSR publishing requirements.

## Local workflow

Install dependencies and run the standard quality gates:

```bash
deno fmt
deno lint
deno test --unstable-kv --allow-read --allow-write
deno task e2e
```

Or use the bundled task:

```bash
deno task check
```

`deno task e2e` requires Docker with Docker Compose. It starts Mailpit and a
containerized Deno test app, executes the E2E suite against the running stack,
and removes the containers afterward.

## GitHub automation

The repository includes four automation files under `.github`:

- `.github/workflows/ci-main.yml` runs `deno task check` and `deno task e2e` on
  pull requests targeting `main`, on every push to `main` (including merges),
  and on manual dispatch.
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

The test suite opens an isolated local Deno KV database file for each test case.
That is why `--unstable-kv`, `--allow-read`, and `--allow-write` are required
for `deno test`.

## Release checklist

1. Update public API docs in `README.md` when behavior changes.
2. Add the release notes to `CHANGELOG.md`.
3. Run `deno task check`.
4. Run `deno task e2e`.
5. Run `deno publish --dry-run` to validate JSR package contents.
6. Publish the package with `deno publish` once the dry run is clean.

## Design notes

- Keep the public API small and explicit.
- Prefer readable control flow over clever abstractions.
- Treat redirect handling, token validation, and cookie serialization as
  security-sensitive areas.
- Keep package docs current with the published API surface.
