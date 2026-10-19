# Dependency update policy

Dependabot is an input to review, not a deployment authority. It may open pull
requests for the frontend npm tree, Python requirements and GitHub Actions, but
no dependency pull request is auto-merged or deployed. The production webhook
remains disabled; production activation stays a manual, immutable-release
operation after CI succeeds.

## Schedule and batching

- npm, pip and GitHub Actions are checked weekly on separate early-morning
  windows in `Europe/Bucharest`.
- Normal version updates wait at least seven days; major releases wait fourteen
  days where semantic-version cooldowns are supported. GitHub security updates
  are not delayed by Dependabot cooldowns.
- npm and Python minor/patch changes are grouped per ecosystem. Major changes
  remain isolated so their migration and rollback implications are reviewable.
- Open version-update pull requests are capped at three per language ecosystem
  and two for Actions. Security-update pull requests use GitHub's separate
  security limit.

## Mandatory review gate

Before merging any dependency update:

1. Read the upstream release notes and security advisory from the project's
   official repository or package publisher. Record breaking behavior, changed
   runtimes, new native code, install hooks, maintainers/ownership changes and
   newly introduced network or telemetry behavior.
2. Confirm the package name, publisher, requested version and registry source.
   Treat an unexpected maintainer, repository move, yanked version or unexplained
   artifact change as a supply-chain incident, not a routine update.
3. Inspect the complete manifest and lock diff. No dependency PR may add registry
   credentials, relax hashes, introduce a moving GitHub Action ref, broaden CI
   permissions, add `pull_request_target`, enable auto-merge or gain deployment
   credentials.
4. For Python runtime changes, regenerate `requirements.lock` from the selected
   binary wheels, retain exactly one SHA-256 hash per exact runtime pin, run
   `scripts/check_requirements_lock.py`, regenerate/check the CycloneDX evidence,
   and keep `requirements.txt` and the lock package sets identical. A Dependabot
   PR that changes only a requirement pin is intentionally not merge-ready.
5. Run the full backend or frontend suite, the operational security tests,
   dependency audit and immutable-Action check. Major framework/runtime changes
   also require focused compatibility tests and an explicit rollback note.
6. Merge only after a human has reviewed the upstream evidence and green CI.
   Build a commit-bound release from the resulting merge commit; never deploy
   Dependabot's branch, an uncommitted lock repair or an unreviewed CI artifact.

## Emergency security updates

For an actively exploitable advisory, skip the normal version cooldown but not
the provenance, hash, test or rollback gates. If a compatible fix is unavailable,
disable or isolate the affected feature first, record the temporary control and
set a dated follow-up. Never suppress an audit finding merely to make CI green.

Repository settings should require the `CI` workflow and human review on the
default branch. This file cannot prove those GitHub account-side controls; they
must be verified in repository settings after the configuration is pushed.
