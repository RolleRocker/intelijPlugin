# OAuth Sample Plugin

IntelliJ Platform plugin demonstrating OAuth 2.0 Authorization Code + PKCE
login with loopback redirect (RFC 8252), following
`oauth-plugin-implementation-plan.md`.

## Configure a provider

Edit the constants at the top of
`src/main/java/com/example/oauthplugin/auth/AuthService.java`:

- `CLIENT_ID`
- `AUTHORIZATION_ENDPOINT`
- `TOKEN_ENDPOINT`
- `SCOPES`

The provider must support PKCE (`S256`) and loopback redirect URIs
(`http://127.0.0.1:<ephemeral-port>/callback`).

## Build

```bash
./gradlew build
```

## Run in a sandbox IDE

```bash
./gradlew runIde
```

## Test

```bash
./gradlew test
```

## Scope

This build is single-module (no JetBrains Split Mode support). See
`oauth-plugin-implementation-plan.md` Phase 8 for the follow-up work
required to support Remote Development / Split Mode, and
`docs/superpowers/specs/2026-09-11-oauth-plugin-design.md` for the design
decisions behind this scaffold.
