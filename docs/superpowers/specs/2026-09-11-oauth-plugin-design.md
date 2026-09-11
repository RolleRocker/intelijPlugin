# Design: OAuth 2.0 IntelliJ Plugin (single-module)

Source requirements: `oauth-plugin-implementation-plan.md` (repo root),
Phases 1-7, 9, 10. Split Mode (Phase 8) is explicitly out of scope for
this build — the source doc itself recommends proving the single-module
flow first.

## Decisions

- **Language:** Java.
- **Scope:** Single Gradle module. No frontend/backend/shared split.
- **Provider:** Generic OIDC. Provider-specific values (`CLIENT_ID`,
  `AUTHORIZATION_ENDPOINT`, `TOKEN_ENDPOINT`, `SCOPES`) are placeholder
  constants at the top of `AuthService`, meant to be filled in for
  whichever PKCE + loopback-redirect-compliant provider is chosen later.
- **Identity:** groupId/package `com.example.oauthplugin`, plugin ID
  `com.example.oauthplugin`, display name "OAuth Sample Plugin".
- **Build tooling:** Gradle with Kotlin DSL build script (`build.gradle.kts`),
  via the IntelliJ Platform Gradle Plugin 2.x. This is standard even for
  Java-language plugins — only the build script is Kotlin, not the plugin
  code.
- **Target platform:** IntelliJ IDEA Community, `sinceBuild` 242 (2024.2+),
  matching the Gradle Plugin 2.x baseline.

## Components

| File | Responsibility |
|---|---|
| `auth/AuthService.java` | Application-level light service (`@Service(Service.Level.APP)`). Owns the full login/logout/refresh/token-storage lifecycle. Implemented per the source doc's Phase 4 reference code, kept as close to verbatim as possible. |
| `auth/AuthenticatedApiClient.java` | Phase 5: injects `Authorization: Bearer`, on 401 calls `invalidateSession()` and fails rather than looping. |
| `actions/LoginAction.java`, `actions/LogoutAction.java` | Registered under Tools menu; call `AuthService#login()` / `#logout()`, report result via `Notifications.Bus`. |
| `settings/OAuthConfigurable.java` + `OAuthSettingsComponent.java` | `Configurable` settings page: shows current login state, sign-in/out button. |
| `statusbar/AuthStatusBarWidget.java` + `AuthStatusBarWidgetFactory.java` | Optional status bar widget showing signed-in/out state at a glance. |
| `META-INF/plugin.xml` | Registers the application service, actions, settings page, and status bar widget factory. |

### Deviation from the source doc's reference code

The pure static helper methods in `AuthService` (`generateCodeVerifier`,
`deriveCodeChallenge`, `generateState`, `buildAuthorizationUrl`, `parseQuery`)
are declared package-private instead of `private`, solely so
`AuthServiceCryptoTest` can call them directly without a running IDE test
fixture. No behavior changes from the doc's reference implementation.

## Testing

- `AuthServiceCryptoTest` (JUnit 5): PKCE verifier/challenge generation
  (format, length, S256 derivation correctness) and authorization-URL
  construction (all required query params present and correctly encoded).
- Out of scope for this pass, called out as follow-up work: platform-fixture
  tests against `PasswordSafe`, mock-HTTP-server integration tests for
  token exchange/refresh, and split-mode testing — these need heavier
  test infrastructure (`BasePlatformTestCase`, WireMock) than a project
  scaffold warrants in one pass.

## Security checklist mapping (Phase 9)

Satisfied by construction in `AuthService`/`AuthenticatedApiClient`: S256
PKCE, freshly generated + validated `state`, loopback bound to
`127.0.0.1` and torn down after use, no client secret in the plugin,
tokens never logged, `PasswordSafe`-only storage, minimum scopes left to
whoever fills in `SCOPES`, HTTPS token endpoint calls via `HttpClient`
with default (untouched) certificate validation, logout clears local
tokens, and a single bounded refresh-then-fail retry on 401 (no loop).
Provider-side revocation-endpoint call on sign-out is not implemented
(most generic OIDC providers don't guarantee one) — noted as a TODO
comment in `logout()` for whoever wires in a real provider.

## Build verification

After scaffolding, run `gradle wrapper` to generate the wrapper, then
`./gradlew build` to confirm the project compiles and packages
end-to-end.
