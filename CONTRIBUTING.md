# Contributing

Thanks for improving `mcp-toolkit-rs`. Keep changes small, explain the
boundary they serve, and preserve the public, provider-neutral scope.

## Before opening a pull request

1. Read the [golden path](docs/golden-path.md) and [toolkit boundary](docs/toolkit-boundary.md) for the affected area.
2. For a new server shape, start with the [starter templates](docs/starter-templates.md) and [delivery lane](docs/new-server-delivery-lane.md).
3. For dependencies, follow [dependency governance](docs/dependency-governance.md). For a release or landing change, follow [cargo package release](docs/cargo-package-release.md) and [public landing policy](docs/public-landing-policy.md).
4. Keep provider credentials, deployment settings, and consumer-local proof in the consuming repository. Do not add secrets or private operational details to this repository.

Pull requests should describe the user-visible contract, affected crates or
docs, compatibility impact, and the hosted checks that prove the change. Keep
deep design rationale in the relevant decision record rather than duplicating
it in an entry-point guide.

## Validation and review

GitHub Actions is the shared validation surface for this repository. Open a
pull request against `main` and wait for the required hosted checks; do not
claim that a local build or an unpublished crate is a release artifact. Review
the generated or consumer-local evidence when a change affects templates,
schemas, policy, authentication, or release behavior.

## Security reports

Please follow [SECURITY.md](SECURITY.md) for vulnerability reports. Use the
private reporting route when available, include a minimal reproduction, and
avoid publishing credentials, tokens, personal data, or internal host details.

## Public wording

This repository is published source. Use neutral, durable terminology in
branches, commits, pull requests, documentation, and workflow output. Review
the final diff for accidental credentials, private URLs, local paths, and
consumer-specific policy before submitting.
