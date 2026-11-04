# Single Go binary with build provenance

driftscan runs with read access to every resource and state file it scans, so how it is installed is a supply-chain decision. It ships as a static Go binary in GitHub Releases with checksums and build provenance attestation; the GitHub Action is a thin composite wrapper that downloads a pinned version and verifies it. No `pip install` or package-manager install at run time, and no Docker image in v1.

## Considered Options

- Python package: faster to write, but resolves dependencies from PyPI on every CI run.
- Docker action: pinnable by digest, but slower start and an image to maintain.
