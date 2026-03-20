# Development

This package is maintained by [synit.io](https://www.synit.io) and is intended
to stay fully compatible with modern Deno and JSR publishing requirements.

## Local workflow

Install dependencies and run the standard quality gates:

```bash
deno fmt
deno lint
deno test --unstable-kv --allow-read --allow-write
```

Or use the bundled task:

```bash
deno task check
```

## Why tests need file permissions

The test suite opens an isolated local Deno KV database file for each test case.
That is why `--unstable-kv`, `--allow-read`, and `--allow-write` are required
for `deno test`.

## Release checklist

1. Update public API docs in `README.md` when behavior changes.
2. Add the release notes to `CHANGELOG.md`.
3. Run `deno task check`.
4. Run `deno publish --dry-run` to validate JSR package contents.
5. Publish the package with `deno publish` once the dry run is clean.

## Design notes

- Keep the public API small and explicit.
- Prefer readable control flow over clever abstractions.
- Treat redirect handling, token validation, and cookie serialization as
  security-sensitive areas.
- Keep package docs current with the published API surface.
