# Handoff: OAuth Sample Plugin

For a fresh Claude Code session picking this up. Read this first, then
`README.md` (user-facing usage) and the docs linked below (design history).

## What this is

An IntelliJ Platform plugin (Java, single Gradle module) implementing OAuth
2.0 Authorization Code + PKCE login with a loopback redirect, per
`oauth-plugin-implementation-plan.md` (the original spec the user supplied).
Built from scratch in this repo across several sessions.

- Design decisions: `docs/superpowers/specs/2026-09-11-oauth-plugin-design.md`
- Implementation plan (task-by-task, includes exact code for the initial
  scaffold): `docs/superpowers/plans/2026-09-11-oauth-plugin-implementation.md`
- User-facing build/run/test instructions: `README.md`

## Current state (as of this handoff)

- `git log --oneline` has 26 commits, all on `master`. **The last 8 commits
  (the round-2 fixes below) are NOT pushed to `origin` yet** (`git status`
  will show "ahead of 'origin/master' by 8 commits") — ask the user before
  pushing, don't assume.
- `./gradlew clean build` passes: compiles, packages, and all 9 unit tests
  in `AuthServiceCryptoTest` pass.
- The plugin has been launched once via `./gradlew runIde` and confirmed to
  start cleanly (Tools menu actions, Settings page, status bar widget all
  present). It has **not** been tested against a real OAuth provider — the
  constants at the top of `AuthService` are still placeholders
  (`your-client-id`, `provider.example.com`).
- Remote: `origin` → `https://github.com/RolleRocker/intelijPlugin.git`
  (this was connected from IntelliJ's side mid-session, not by Claude).
- A shareable IntelliJ run configuration exists at
  `.run/Run IDE with Plugin.run.xml` (runs the `runIde` Gradle task).

## How this was built

1. Brainstorming skill → architectural path → design spec → implementation
   plan → executed inline in-session (see the two docs linked above).
2. Two full-repo code reviews have been run so far via
   `/code-review high --target root..HEAD`, each followed by fixes:
   - **Round 1** (6 findings, all fixed, commits `dced41d`..`9963493`):
     reflected XSS in the callback HTML, a refresh-token race, a dead status
     bar widget that never repainted, a settings panel that read stale state
     after async logout, EDT-blocking `PasswordSafe` reads, and
     `AuthenticatedApiClient` not reusing the shared `HttpClient`.
   - **Round 2** (10 findings, all fixed), run after round 1's fixes plus 3
     more requested additions (proxy support, cancellable login progress,
     401-triggers-warning). First 2 fixed in commits `0e91902`, `9235590`,
     `6f88a28`; remaining 8 fixed on 2026-10-15 (commits `6eee6bd`..`9231286`,
     listed below).

## Open findings from the round-2 review — all fixed (2026-10-15)

All 8 findings below were fixed in individual commits (`6eee6bd`, `aa8b1cc`,
`e4429bf`, `75dc6c8`, `ab482e5`, `229c658`, `ff3e14c`, `9231286`), each
verified with `./gradlew test` before committing. Kept here for context on
what the bugs were; don't re-report these unless a regression reintroduces
them.

1. **Security + correctness, `AuthService.handleCallback()`**: the
   `error` query param is HTML-escaped before going into the browser page
   (fixed in round 1), but the *same raw, unescaped* value is still used
   verbatim as the `AuthException` message, which ends up in the IDE's
   "Sign-in failed" notification body. Also, this error branch runs
   **before** the `state` (CSRF) check, so a local process can hit
   `.../callback?error=<crafted text>` during the login window without
   knowing the random state token. Fix: escape before building the
   exception message too, and/or check `state` before checking `error`.

2. **Correctness, `AuthService.postForToken()`**: no connect/response
   timeout is set on the `HttpClient` or the `HttpRequest`, and this runs on
   the single-thread `authExecutor` shared by `login()`/`logout()`/
   `getValidAccessToken()`. If the token endpoint accepts the TCP connection
   but never responds, that thread — and therefore all future auth
   operations for the rest of the IDE session — hangs forever. Fix: add
   `.connectTimeout(...)` to the `HttpClient` builder and `.timeout(...)` to
   the request builder.

3. **Correctness, `AuthService.refreshAccessToken()`**: the `catch
   (Exception e)` around the refresh call clears the *entire* stored session
   on any failure, including a transient network blip or a 502/503 — not
   just a genuine "refresh token rejected" response. Fix: only clear on a
   response that actually indicates the refresh token is invalid (e.g. HTTP
   400/401 from the token endpoint), not on `IOException`/timeouts.

4. **Correctness, `AuthService.storeTokens()`**: if a token response omits
   `expires_in` (legal per OAuth2), `accessTokenExpiry` is never written, so
   `getValidAccessToken()`'s expiry check defaults to "expired" forever.
   Combined with no `refresh_token`, `isLoggedIn()` reports `true` (token
   presence only) while `getValidAccessToken()` perpetually throws
   `NotAuthenticatedException` — a stuck state with no obvious way out for
   the user. Fix: decide a sane default expiry when absent, or treat a
   missing `expires_in` + missing `refresh_token` as a hard login failure
   up front.

5. **Correctness, `AuthService.login()`**: the CAS-failure fallback path
   does `return inFlightLogin.get();` instead of retrying its own CAS loop —
   under a 3-way race it can hand the caller a future for a completely
   unrelated, newer login attempt. Fix: loop (re-read `existing`, retry the
   CAS) instead of a single fallback read.

6. **Correctness, `AuthService.handleCallback()`**: on the error/state-
   mismatch path, `codeFuture.completeExceptionally(...)` unblocks
   `runLoginFlow`, which then runs `finally { server.stop(0); }` — this can
   race the callback handler thread still writing the HTTP response body,
   so the browser sometimes sees a truncated/reset connection instead of
   the friendly "Authentication failed" page. Fix: complete the future
   *after* the response is fully written, or delay `server.stop(0)`
   slightly.

7. **Correctness, `OAuthSettingsComponent.onAuthActionComplete()`**: the
   `throwable` from `login()`/`logout()` is discarded — a failed sign-in
   triggered from the Settings page shows no error at all (just the button
   flipping back), unlike `LoginAction`'s Tools-menu path which shows an
   ERROR notification for the identical failure. Fix: thread the throwable
   through and show the same kind of notification (or an inline label).

8. **Correctness (minor), `AuthStatusBarWidget`**: the `statusBar` field is
   not `volatile`; `refreshState()` reads it on a pooled thread while
   `dispose()` nulls it on the EDT with no synchronization. Narrow window,
   low real-world impact, but worth a `volatile` (or reading it once into a
   local under a lock) for correctness.

**Already fixed in round 2** (don't re-report if a future review flags
these again after checking commit `6f88a28`/`0e91902`):
`invalidateSession()` now runs on `authExecutor` instead of the caller's
thread; `AuthenticatedApiClient`'s 401 path now calls
`AuthStatusBarWidget.refreshAll()` and shows a warning notification.

## Suggested next steps (pick up here)

1. All commits through `9231286` are on `master` but **not pushed to
   `origin` yet** — ask the user before pushing.
2. Longer-term, still out of scope per earlier explicit decisions:
   - Split Mode / Remote Development support (Phase 8 of the original plan
     doc) — deliberately deferred, build single-module first.
   - Deeper test coverage: a `PasswordSafe`-backed platform-fixture test,
     and a mock-HTTP-server integration test for token exchange/refresh
     (Phase 10 of the plan doc). Only pure-function unit tests exist today.
   - No revocation-endpoint call on sign-out (there's a `TODO` comment in
     `AuthService.logout()`).

## Gotchas learned the hard way this session

- **IntelliJ Platform Gradle Plugin 2.x requires Gradle 9.0+.** The wrapper
  is pinned to Gradle 9.5.0 (`gradle/wrapper/gradle-wrapper.properties`) —
  don't downgrade it, the build fails fast with a clear error if you do.
- **Gradle 9's `test` task needs `junit-platform-launcher` explicitly** on
  `testRuntimeOnly` — it's not pulled in transitively anymore.
- **`com.intellij.util.net.PlatformHttpClient` is `@since 2025.2` and
  `@ApiStatus.Experimental`** — do NOT use it; this project targets
  `sinceBuild` 242 (2024.2). Use `com.intellij.util.net.JdkProxyProvider`
  instead (`getInstance().getProxySelector()` /
  `.getAuthenticator()`) — verified present as a stable, non-deprecated
  public API by decompiling the actual resolved 2024.2.6 platform jar in
  `~/.gradle/caches/9.5.0/transforms/*/transformed/ideaIC-2024.2.6-win/lib/app-client.jar`
  (`javap -p` on `com/intellij/util/net/JdkProxyProvider.class`). When in
  doubt about whether a platform API exists on the target version, check the
  actual resolved jar rather than trusting the latest `intellij-community`
  master source (which reflects a much newer/future platform version).
- The `.intellijPlatform/` directory (created by the Gradle plugin at the
  project root, ~160MB) is gitignored — don't try to commit it if you see it
  show up as untracked.
- Line-ending warnings from git (`LF will be replaced by CRLF`) on every
  commit are expected on this Windows checkout and harmless.
