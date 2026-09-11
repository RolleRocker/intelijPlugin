# Implementation Plan: OAuth 2.0 Authentication for an IntelliJ Plugin

## Goal

Add sign-in capability to an IntelliJ Platform plugin so it can authenticate the
user to an external service (our own backend, a SaaS API, or a third-party
provider like GitHub/Google/Okta/Auth0) and make authenticated API calls on
their behalf. No client secret is embedded in the plugin; no personal access
tokens are pasted into settings by the user.

**Flow used:** OAuth 2.0 Authorization Code flow with PKCE, loopback redirect
(RFC 8252 — OAuth for Native Apps). This is the standard, correct pattern for
any desktop application, including IDE plugins.

This document is a full build plan, including a reference implementation of
the core `AuthService` class and specific guidance for making the feature work
correctly under JetBrains Split Mode (Remote Development). Follow it phase by
phase; each phase produces something testable before moving to the next.

---

## Phase 0 — Decisions to confirm before writing code

1. **Confirm the identity provider supports PKCE + loopback redirects.**
   Almost all modern providers do (Google, GitHub, Okta, Auth0, Microsoft
   Entra, generic OIDC). If we control the backend ourselves, build it to
   this spec.
2. **Scope granularity.** Request the minimum scopes the plugin actually
   needs. Broad scopes are a bigger attack surface and will get flagged in
   JetBrains Marketplace security review.
3. **Token lifetime strategy.** Request `offline_access` (OIDC) or the
   provider's equivalent if we want a refresh token / long-lived session
   rather than forcing re-login whenever the access token expires.
4. **Storage scope.** Use **application-level** storage (not per-project) —
   users should not have to log in again for every project they open.

---

## Phase 1 — Register the plugin as an OAuth client

With the chosen identity provider (or our own auth server):

- Register a new **public client** (not confidential — no secret; a desktop
  binary can't keep one confidential).
- Register the **redirect URI(s)**. Since the callback is a local loopback
  server on an ephemeral port, register:
  - `http://127.0.0.1/callback` if the provider allows wildcard ports, or
  - a fixed port, e.g. `http://127.0.0.1:38271/callback`, if the provider
    requires an exact match (check this — it constrains the local server
    design in Phase 5).
- Note the **authorization endpoint**, **token endpoint**, and (if OIDC) the
  **discovery document** (`/.well-known/openid-configuration`).
- Obtain the **Client ID**. There is no secret to store.

---

## Phase 2 — Plugin project setup

- **No extra HTTP server dependency needed.** The JDK ships
  `com.sun.net.httpserver.HttpServer`, sufficient for a single-shot loopback
  listener.
- **No extra HTTP client dependency needed.** `java.net.http.HttpClient`
  (JDK 11+) is already available for the token exchange call.
- **No extra JSON library dependency needed.** Gson (`com.google.gson`) is
  bundled with the IntelliJ Platform SDK.
- **No extra credential-storage dependency needed.** `PasswordSafe`
  (`com.intellij.ide.passwordSafe.PasswordSafe`) is part of the platform SDK.
- If the plugin is written in Kotlin, this flow maps naturally onto
  coroutines using the platform's own coroutine scope APIs, rather than
  blocking the EDT (UI thread) with network calls.

---

## Phase 3 — Architecture / components

Build these as distinct classes:

| Component | Responsibility |
|---|---|
| `OAuthConfig` | Constants: client ID, endpoints, scopes |
| `PkceGenerator` | Generates `code_verifier` / `code_challenge` |
| `LoopbackServer` | Starts a local HTTP listener, captures the redirect, shuts itself down |
| `AuthorizationUrlBuilder` | Builds the browser URL with all required params |
| `TokenExchangeClient` | POSTs to the token endpoint, parses the response |
| `TokenStore` | Wraps `PasswordSafe` for secure persistence |
| `AuthService` | Application-level service orchestrating the whole flow; exposes `login()`, `logout()`, `getValidAccessToken()` — see Phase 4 for the full reference implementation |
| `AuthenticatedApiClient` | Wraps actual API calls, injecting the bearer token, handling 401 → refresh → retry |
| UI: `LoginAction`, `LogoutAction` | Registered actions, e.g. under Tools menu |
| UI: settings `Configurable` | Shows current login state, sign-in/out button |
| UI: status bar widget (optional) | Shows login state at a glance |

Register `AuthService` as an **application-level light service**
(`@Service(Service.Level.APP)` annotation, or `<applicationService>` in
`plugin.xml` for older IDE targets) — this gives a singleton, lazily
instantiated, with a lifecycle IntelliJ manages automatically.

---

## Phase 4 — Reference implementation: `AuthService`

Implement this class as-is (adjust the provider constants at the top). It
covers PKCE/state generation, the loopback listener, browser launch, token
exchange, refresh, and secure storage in one cohesive service.

```java
package com.example.plugin.auth;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.intellij.credentialStore.CredentialAttributes;
import com.intellij.credentialStore.CredentialAttributesKt;
import com.intellij.credentialStore.Credentials;
import com.intellij.ide.BrowserUtil;
import com.intellij.ide.passwordSafe.PasswordSafe;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.diagnostic.Logger;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Application-level service that owns the full OAuth 2.0 Authorization Code
 * + PKCE lifecycle for this plugin: login, token storage, silent refresh,
 * and logout.
 *
 * Registered as a light application service - IntelliJ instantiates this
 * lazily as a singleton. Declare it in plugin.xml if targeting IDE versions
 * that don't support the @Service(Service.Level.APP) annotation alone:
 *
 * <applicationService serviceImplementation="com.example.plugin.auth.AuthService"/>
 */
@Service(Service.Level.APP)
public final class AuthService {

    private static final Logger LOG = Logger.getInstance(AuthService.class);

    // ---- Provider configuration - replace with your actual values ----
    private static final String CLIENT_ID = "your-client-id";
    private static final String AUTHORIZATION_ENDPOINT = "https://provider.example.com/oauth/authorize";
    private static final String TOKEN_ENDPOINT = "https://provider.example.com/oauth/token";
    private static final String SCOPES = "openid profile offline_access";
    private static final String CREDENTIAL_SERVICE_NAME = "MyOAuthPlugin";
    private static final int LOGIN_TIMEOUT_SECONDS = 300; // 5 minutes
    private static final long EXPIRY_SAFETY_MARGIN_SECONDS = 60;

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Gson gson = new Gson();
    private final ExecutorService authExecutor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "oauth-auth-service");
                t.setDaemon(true);
                return t;
            });

    // Guards against two concurrent login attempts racing each other.
    private final AtomicReference<CompletableFuture<Void>> inFlightLogin = new AtomicReference<>();

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Starts (or joins) an interactive login flow. Safe to call from the EDT;
     * all blocking work happens on a background executor. The browser is
     * opened as a side effect; the returned future completes once tokens are
     * stored, or completes exceptionally on failure/timeout/cancellation.
     */
    public CompletableFuture<Void> login() {
        CompletableFuture<Void> existing = inFlightLogin.get();
        if (existing != null && !existing.isDone()) {
            return existing;
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        if (!inFlightLogin.compareAndSet(existing, future)) {
            // Another thread won the race to start a login; join it instead.
            return inFlightLogin.get();
        }

        authExecutor.submit(() -> runLoginFlow(future));
        return future;
    }

    /** Clears local session state. Does not block the EDT. */
    public void logout() {
        authExecutor.submit(() -> {
            clearStoredTokens();
            LOG.info("User signed out; local tokens cleared.");
        });
    }

    /** True if a (possibly expired) session exists locally. */
    public boolean isLoggedIn() {
        return readCredential(tokenKey("refreshToken")) != null
                || readCredential(tokenKey("accessToken")) != null;
    }

    /**
     * Returns a currently-valid access token, refreshing first if necessary.
     * Throws NotAuthenticatedException if there is no usable session.
     * This performs blocking network I/O when a refresh is needed - call it
     * off the EDT.
     */
    public String getValidAccessToken() {
        String accessToken = readCredential(tokenKey("accessToken"));
        String expiryStr = readCredential(tokenKey("accessTokenExpiry"));

        boolean expired = true;
        if (accessToken != null && expiryStr != null) {
            Instant expiry = Instant.parse(expiryStr);
            expired = Instant.now().plusSeconds(EXPIRY_SAFETY_MARGIN_SECONDS).isAfter(expiry);
        }

        if (!expired) {
            return accessToken;
        }

        String refreshToken = readCredential(tokenKey("refreshToken"));
        if (refreshToken == null) {
            throw new NotAuthenticatedException("No refresh token available; user must sign in.");
        }

        return refreshAccessToken(refreshToken);
    }

    /** Forces the next getValidAccessToken() call to require a fresh login. */
    public void invalidateSession() {
        clearStoredTokens();
    }

    // ------------------------------------------------------------------
    // Login flow internals
    // ------------------------------------------------------------------

    private void runLoginFlow(CompletableFuture<Void> resultFuture) {
        HttpServer server = null;
        try {
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = deriveCodeChallenge(codeVerifier);
            String state = generateState();

            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            int port = server.getAddress().getPort();
            String redirectUri = "http://127.0.0.1:" + port + "/callback";

            CompletableFuture<String> codeFuture = new CompletableFuture<>();
            server.createContext("/callback", exchange ->
                    handleCallback(exchange, state, codeFuture));
            server.setExecutor(null); // default executor is fine for a single short-lived request
            server.start();

            String authUrl = buildAuthorizationUrl(redirectUri, state, codeChallenge);
            LOG.info("Opening browser for OAuth login.");
            ApplicationManager.getApplication().invokeLater(() -> BrowserUtil.browse(authUrl));

            String code;
            try {
                code = codeFuture.get(LOGIN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                throw new AuthException("Login timed out waiting for browser callback.", e);
            }

            TokenResponse tokens = exchangeCodeForTokens(code, redirectUri, codeVerifier);
            storeTokens(tokens);

            LOG.info("OAuth login succeeded.");
            resultFuture.complete(null);
        } catch (Exception e) {
            LOG.warn("OAuth login failed", e);
            resultFuture.completeExceptionally(e);
        } finally {
            if (server != null) {
                server.stop(0);
            }
        }
    }

    private void handleCallback(com.sun.net.httpserver.HttpExchange exchange,
                                 String expectedState,
                                 CompletableFuture<String> codeFuture) throws IOException {
        try {
            Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());
            String error = params.get("error");
            String returnedState = params.get("state");
            String code = params.get("code");

            String message;
            if (error != null) {
                message = "Authentication failed: " + error + ". You can close this window.";
                codeFuture.completeExceptionally(new AuthException("Provider returned error: " + error));
            } else if (returnedState == null || !returnedState.equals(expectedState)) {
                message = "Security check failed. You can close this window.";
                codeFuture.completeExceptionally(new AuthException("OAuth state mismatch - possible CSRF attempt."));
            } else if (code == null) {
                message = "No authorization code received. You can close this window.";
                codeFuture.completeExceptionally(new AuthException("Missing 'code' parameter in callback."));
            } else {
                message = "Signed in. You can close this window and return to the IDE.";
                codeFuture.complete(code);
            }

            byte[] out = ("<html><body style=\"font-family:sans-serif;padding:2em;\">"
                    + message + "</body></html>").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
        } finally {
            exchange.close();
        }
    }

    private String buildAuthorizationUrl(String redirectUri, String state, String codeChallenge) {
        return AUTHORIZATION_ENDPOINT
                + "?response_type=code"
                + "&client_id=" + encode(CLIENT_ID)
                + "&redirect_uri=" + encode(redirectUri)
                + "&scope=" + encode(SCOPES)
                + "&state=" + encode(state)
                + "&code_challenge=" + encode(codeChallenge)
                + "&code_challenge_method=S256";
    }

    // ------------------------------------------------------------------
    // Token exchange / refresh
    // ------------------------------------------------------------------

    private TokenResponse exchangeCodeForTokens(String code, String redirectUri, String codeVerifier) {
        String body = "grant_type=authorization_code"
                + "&code=" + encode(code)
                + "&redirect_uri=" + encode(redirectUri)
                + "&client_id=" + encode(CLIENT_ID)
                + "&code_verifier=" + encode(codeVerifier);

        return postForToken(body);
    }

    private String refreshAccessToken(String refreshToken) {
        String body = "grant_type=refresh_token"
                + "&refresh_token=" + encode(refreshToken)
                + "&client_id=" + encode(CLIENT_ID);

        try {
            TokenResponse tokens = postForToken(body);
            storeTokens(tokens);
            return tokens.accessToken;
        } catch (Exception e) {
            LOG.info("Refresh failed; clearing local session.", e);
            clearStoredTokens();
            throw new NotAuthenticatedException("Session expired; please sign in again.", e);
        }
    }

    private TokenResponse postForToken(String formBody) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(TOKEN_ENDPOINT))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 != 2) {
                throw new AuthException("Token endpoint returned HTTP " + response.statusCode()
                        + ": " + response.body());
            }

            TokenResponse parsed = gson.fromJson(response.body(), TokenResponse.class);
            if (parsed == null || parsed.accessToken == null) {
                throw new AuthException("Token endpoint response missing access_token.");
            }
            return parsed;
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthException("Network error during token exchange.", e);
        }
    }

    // ------------------------------------------------------------------
    // Storage - PasswordSafe backs onto OS-native secure storage
    // ------------------------------------------------------------------

    private void storeTokens(TokenResponse tokens) {
        writeCredential(tokenKey("accessToken"), tokens.accessToken);

        if (tokens.refreshToken != null) {
            writeCredential(tokenKey("refreshToken"), tokens.refreshToken);
        }

        if (tokens.expiresInSeconds != null) {
            Instant expiry = Instant.now().plusSeconds(tokens.expiresInSeconds);
            writeCredential(tokenKey("accessTokenExpiry"), expiry.toString());
        }
    }

    private void clearStoredTokens() {
        writeCredential(tokenKey("accessToken"), null);
        writeCredential(tokenKey("refreshToken"), null);
        writeCredential(tokenKey("accessTokenExpiry"), null);
    }

    private String readCredential(CredentialAttributes attributes) {
        Credentials creds = PasswordSafe.getInstance().get(attributes);
        return creds != null ? creds.getPasswordAsString() : null;
    }

    private void writeCredential(CredentialAttributes attributes, String value) {
        if (value == null) {
            PasswordSafe.getInstance().set(attributes, null);
        } else {
            PasswordSafe.getInstance().set(attributes, new Credentials("oauth-user", value));
        }
    }

    private CredentialAttributes tokenKey(String suffix) {
        return new CredentialAttributes(
                CredentialAttributesKt.generateServiceName(CREDENTIAL_SERVICE_NAME, suffix));
    }

    // ------------------------------------------------------------------
    // PKCE / state generation
    // ------------------------------------------------------------------

    private static String generateCodeVerifier() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String deriveCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every JDK; this is unreachable in practice.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String generateState() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // ------------------------------------------------------------------
    // Small utilities
    // ------------------------------------------------------------------

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> result = new HashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return result;
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            result.put(key, value);
        }
        return result;
    }

    // ------------------------------------------------------------------
    // DTOs / exceptions
    // ------------------------------------------------------------------

    private static final class TokenResponse {
        @SerializedName("access_token")
        String accessToken;

        @SerializedName("refresh_token")
        String refreshToken;

        @SerializedName("expires_in")
        Long expiresInSeconds;

        @SerializedName("token_type")
        String tokenType;
    }

    public static class AuthException extends RuntimeException {
        public AuthException(String message) {
            super(message);
        }

        public AuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class NotAuthenticatedException extends RuntimeException {
        public NotAuthenticatedException(String message) {
            super(message);
        }

        public NotAuthenticatedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
```

Design notes to preserve when implementing:

- `inFlightLogin` prevents two `login()` calls (two IDE windows, a double
  click) from racing to start two loopback servers on different ports at
  once.
- The single-thread `authExecutor` serializes all OAuth state transitions so
  a refresh and a fresh login can never race to write tokens simultaneously.
- `getValidAccessToken()` is synchronous/blocking by design — call it from a
  background thread already making the API call
  (`ApplicationManager.getApplication().executeOnPooledThread(...)`), never
  from the EDT.
- `PasswordSafe.set(attributes, null)` is the documented way to delete a
  stored credential; `clearStoredTokens()` relies on this for logout.

---

## Phase 5 — Making authenticated API calls

Centralize bearer-token injection and 401 handling in one place rather than
scattering it across call sites:

```java
public <T> T call(HttpRequest.Builder requestBuilder, ...) {
    String token = authService.getValidAccessToken(); // handles refresh internally
    HttpRequest request = requestBuilder
        .header("Authorization", "Bearer " + token)
        .build();
    HttpResponse<String> resp = client.send(request, ...);
    if (resp.statusCode() == 401) {
        // token was revoked server-side unexpectedly - force full re-auth, don't loop
        authService.invalidateSession();
        throw new NotAuthenticatedException();
    }
    return parse(resp);
}
```

---

## Phase 6 — UI integration

- **Actions**: `Sign In` / `Sign Out`, registered in `plugin.xml` under a
  `<group>`, placed somewhere discoverable (Tools menu or a dedicated plugin
  menu).
- **Settings page**: implement `Configurable`, show current login state
  ("Signed in as ...") and a sign-in/out button.
- **Status indication**: optional status bar widget or notification
  (`Notifications.Bus`) confirming successful login/logout, and warning on
  auth failures.
- **Startup check**: on plugin/project load, check `AuthService.isLoggedIn()`
  for a valid stored session so the user isn't asked to log in every IDE
  restart.

---

## Phase 7 — Error handling and edge cases

Handle each of these explicitly — this is where most OAuth plugin bugs live:

- **User closes the browser tab** without completing login → the
  `codeFuture` timeout fires (`LOGIN_TIMEOUT_SECONDS`), clean up the server,
  show a cancellable "waiting for sign-in..." UI the user can dismiss.
- **Port already in use** (only relevant if a fixed port is required by the
  provider) → catch `BindException`, retry with backoff or surface a clear
  error.
- **Multiple IDE windows/projects logging in simultaneously** → already
  guarded by `inFlightLogin` in the reference implementation.
- **Clock skew** affecting expiry checks → the `EXPIRY_SAFETY_MARGIN_SECONDS`
  constant already builds in a safety margin; don't remove it.
- **Corporate proxies / SSL interception** → make sure `HttpClient` respects
  IDE-configured proxy settings (`HttpConfigurable` in the platform) rather
  than only system defaults.
- **User revokes access on the provider's side** → the next 401 triggers
  `invalidateSession()` and clean re-auth, not a crash loop.
- **Remote Development / Split Mode** → see the dedicated section below.
  This is the single most commonly missed case; do not skip it.

---

## Phase 8 — Split Mode (Remote Development) — required reading

**Do not treat this as a runtime "detect remote dev and show a fallback"
problem.** That is not how JetBrains' own architecture works, and trying to
patch it in with an environment check will not reliably work. The correct
fix is architectural.

### Why the naive approach breaks

In Split Mode, the IDE is two processes: a **frontend** (runs on the user's
machine, renders UI) and a **backend** (holds the project model, does
indexing/execution/heavy work, and can live on another machine, in a
container, or in the cloud). If `AuthService` — including its
`BrowserUtil.browse()` call and its loopback `HttpServer` — runs on the
**backend**, then:

- "Open a browser" tries to open a browser on whatever machine hosts the
  backend, which may be a headless container with no browser at all.
- A loopback server bound to `127.0.0.1` on the backend is not reachable by
  the browser that opened on the user's actual (frontend) machine.

This is a documented failure mode, not a hypothetical: JetBrains' Split Mode
docs specifically warn plugin authors not to assume frontend and backend
share a machine, and other JetBrains-ecosystem plugins have shipped bugs
where backend-only code accidentally ran on the frontend (or vice versa).

### The correct fix: build this as a split plugin

Structure the plugin into three Gradle modules — **frontend**, **backend**,
and **shared** — so each piece of code runs on the side it belongs on.

```kotlin
// build.gradle.kts
intellijPlatform {
    splitMode = true
    splitModeTarget = SplitModeAware.SplitModeTarget.BOTH
}
```

`splitModeTarget` controls where each module's code is installed:
- `FRONTEND` — UI-only code
- `BACKEND` — project-model / heavy-lifting code
- `BOTH` — the typical shape for a modular plugin containing all three
  module types

### Where `AuthService` belongs

The login flow is fundamentally **frontend-machine work** — it opens a
browser and listens on a loopback port on whatever machine the browser is
running on, which is the frontend machine.

- **Frontend module**: PKCE/state generation, browser launch, the loopback
  listener, the code-for-token exchange. This is effectively the
  `AuthService` class from Phase 4, moved into the `frontend` module.
- **Backend module**: any code that needs to make authenticated API calls
  using the resulting token.
- Getting the token from frontend to backend uses the platform's **RPC**
  mechanism, not ad hoc storage or polling:
  1. A **shared module** declares the RPC interface using the `rpc` Gradle
     plugin plus Kotlin serialization.
  2. The **frontend module** implements the login side of that interface.
  3. The **backend module** calls the RPC interface to obtain tokens rather
     than touching credential storage directly.

  ```
  shared/   -> interface AuthRpc {
                   suspend fun storeTokens(tokens: TokenPayload)
                   suspend fun getValidAccessToken(): String
               }
  frontend/ -> runs the OAuth flow (browser, loopback server), then calls
               AuthRpc.storeTokens(...) to ship the result to the backend
  backend/  -> implements the backend side of AuthRpc; API-calling code asks
               *this* for a token instead of reading PasswordSafe directly
  ```

- **`PasswordSafe` storage belongs on the frontend**, since that's the
  user's actual machine with their OS keychain. Storing secrets on an
  ephemeral backend container would be worse, not better. The backend should
  request a token via RPC each time it needs one rather than caching a
  long-lived local copy.

### Settings sync (if applicable)

If the plugin exposes OAuth-related settings (e.g. a custom OAuth server URL
for enterprise users), Split Mode has a dedicated, already-solved mechanism
for keeping `PersistentStateComponent` settings in sync between frontend and
backend: `RemoteSettingInfoProvider`, plus explicit sync-direction
configuration. Do not build custom polling or ad hoc sync for this.

### Build and test order for split-mode support

1. Build and prove the OAuth flow as a **single-module, non-split plugin
   first**, exactly as described in Phases 1–7. Get the mechanics correct in
   isolation before adding module-splitting complexity.
2. Split it: move the login flow into the `frontend` module, define the
   `AuthRpc` shared interface, make backend code consume tokens exclusively
   via RPC.
3. Test with `runIdeSplitMode` — a dedicated Gradle task that runs frontend
   and backend as genuinely separate local processes, to catch
   cross-boundary mistakes before a real remote deployment does.
4. Only after that, test against an actual remote backend (a second machine
   or container) to catch anything local split-mode simulation might miss —
   e.g. network latency affecting the login timeout, or proxy/TLS
   differences.

**Known rough edge:** Multi-account OAuth in split-mode plugins is an area
where practitioners still report friction and provider-specific quirks.
JetBrains' own guidance on this pattern is fairly recent (mid-2026). Check
the official sample repository (`JetBrains/intellij-sdk-docs`, under
`code_samples/oauth2`) for updates before shipping.

---

## Phase 9 — Security checklist before shipping

- [ ] PKCE (`S256`, not `plain`) used on every auth request
- [ ] `state` generated fresh per attempt and validated before trusting the
      returned code
- [ ] Loopback server bound to `127.0.0.1` only, torn down immediately after
      use
- [ ] No client secret embedded anywhere in the plugin JAR
- [ ] Tokens never logged, never written to plain files, never included in
      exception messages sent to telemetry
- [ ] Tokens stored exclusively via `PasswordSafe` (frontend-side in a
      split-mode build)
- [ ] Minimum necessary scopes requested
- [ ] Token exchange and refresh calls use HTTPS with certificate validation
      untouched
- [ ] Sign-out clears local tokens and, if the provider supports it, calls
      its revocation endpoint
- [ ] 401 responses trigger a bounded retry (refresh-then-retry once), never
      an infinite loop

---

## Phase 10 — Testing strategy

- **Unit test** PKCE generation and authorization-URL building in isolation
  — pure functions, no network needed.
- **Unit test** token storage against a fake/in-memory `PasswordSafe` if the
  platform test fixtures support it, or via `BasePlatformTestCase` for a
  real lightweight IDE instance.
- **Integration test** the token exchange/refresh logic against a mock HTTP
  server (`com.sun.net.httpserver.HttpServer` or WireMock) simulating
  provider responses, including error cases (expired code, invalid grant,
  revoked token).
- **Manual end-to-end test** against the real provider using a
  sandboxed/dev OAuth app registration (not production credentials) —
  verify the full browser round-trip, including cancel and timeout paths.
- **Split-mode test** via `runIdeSplitMode` as described in Phase 8.

---

## Suggested overall build order

1. Phase 1 (provider registration) → Phase 4 as a throwaway console/test
   harness first, to prove the raw OAuth flow works outside the IDE.
2. Wrap it into the actual `AuthService` inside the plugin (Phase 3–4).
3. Add storage, refresh, and the API wrapper (Phase 4–5).
4. Add UI last (Phase 6) — by then the underlying flow is already proven,
   so UI work doesn't get tangled with debugging OAuth mechanics.
5. Apply the Split Mode module restructuring (Phase 8) once the
   single-module version works end to end.
6. Run the security checklist (Phase 9) and testing pass (Phase 10)
   continuously alongside each step above, not as a final pass at the end.
