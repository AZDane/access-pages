# Repository instructions

## Protected main branch

Treat `main` as the protected, releasable branch. For every change to this
repository:

1. Create or use a feature branch. Do not push commits directly to `main`.
2. Push the feature branch and open a pull request targeting `main`.
3. Do not merge until all required GitHub checks pass:
   - Static analysis and tests
   - Secret scanning
   - Dependencies and repository configuration
   - Container image
4. Resolve all required pull request conversations before merging.

Do not bypass or weaken the `main` branch ruleset.

## Home Assistant release completion

The intended permanent public release uses two GitHub repositories. Create
them only when publication is explicitly authorized:

- `AZDane/access-pages` contains the application source and publishes
  the versioned container image.
- `AZDane/access-pages-app` is the public Home Assistant App Store repository.

A Home Assistant App release is not complete when the container image is
published. For every release, complete and verify all of the following:

1. Update the version and changelog in `homeassistant-app/` here.
2. Commit the source changes on a feature branch, push it, and merge its pull
   request into `main` after the required checks and conversations are clear.
3. Publish the matching `v<version>` GitHub release and wait for validation,
   both architecture images, the multi-architecture manifest, and signing.
4. Synchronize these files to `AZDane/access-pages-app`:
   - `homeassistant-app/config.yaml`
   - `homeassistant-app/README.md`
   - `homeassistant-app/DOCS.md`
   - `homeassistant-app/CHANGELOG.md`
   - `homeassistant-app/apparmor.txt`
   - `homeassistant-app/icon.png`
   - `homeassistant-app/logo.png`
   Verify that each synchronized file is byte-for-byte identical in both
   repositories before completing the release.
5. Update the public repository's root `README.md` and `repository.yaml` when
   product naming, ownership, installation URLs, or maintainers change.
6. Commit and push the public App Store repository, then verify its default
   branch advertises the same version as the published container image.

Do not report a release as fully published until both repositories are current.
Preserve the `access_pages` App slug, `ghcr.io/azdane/access-pages-app` image
path, and genuine LayerV technology identifiers unless the task explicitly
includes a migration of those identifiers.
