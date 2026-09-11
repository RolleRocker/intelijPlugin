# OAuth Sample Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold a buildable, single-module IntelliJ IDEA plugin (Java) implementing OAuth 2.0 Authorization Code + PKCE login, per the source plan's Phases 1-7, 9, 10.

**Architecture:** One Gradle module built with the IntelliJ Platform Gradle Plugin 2.x. An application-level `AuthService` light service owns the full login/refresh/logout lifecycle (browser-based PKCE flow, loopback HTTP callback, `PasswordSafe` storage). `AuthenticatedApiClient` centralizes bearer-token injection and 401 handling. Thin UI layer (two actions, a settings page, a status bar widget) surfaces login state and lets the user sign in/out.

**Tech Stack:** Java 21 (toolchain), Gradle Kotlin DSL, IntelliJ Platform Gradle Plugin 2.16.0, target platform IntelliJ IDEA Community 2024.2.6 (`sinceBuild` 242), JUnit 5 for unit tests, Gson + JDK `HttpClient`/`HttpServer` (all bundled with the platform/JDK — no extra runtime deps).

**Spec:** `docs/superpowers/specs/2026-09-11-oauth-plugin-design.md`

## Global Constraints

- Package/group: `com.example.oauthplugin`. Plugin ID: `com.example.oauthplugin`. Display name: "OAuth Sample Plugin".
- Split Mode (Phase 8 of the source doc) is out of scope. Do not create frontend/backend/shared modules.
- `AuthService` follows the source doc's Phase 4 reference implementation as closely as possible; the only intentional deviations are: package name, and the pure static crypto/URL/query-parsing helper methods made package-private (dropping `private`) and `buildAuthorizationUrl` made `static` so `AuthServiceCryptoTest` can call them directly. No other behavior changes.
- No client secret anywhere. No token ever logged or included in an exception message.
- Every task must leave `./gradlew build` passing before moving to the next task.

---

### Task 1: Gradle project scaffold

**Files:**
- Create: `settings.gradle.kts`
- Create: `build.gradle.kts`
- Create: `gradle.properties`
- Create: `.gitignore`
- Create: `src/main/resources/META-INF/plugin.xml` (minimal skeleton, extended in later tasks)

**Interfaces:**
- Produces: a Gradle project buildable via `./gradlew build`, targeting IntelliJ IDEA Community 2024.2.6, Java 21 toolchain, JUnit 5 test runner wired up.

- [ ] **Step 1: Create `settings.gradle.kts`**

```kotlin
import org.jetbrains.intellij.platform.gradle.extensions.intellijPlatform

rootProject.name = "oauth-sample-plugin"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
    id("org.jetbrains.intellij.platform.settings") version "2.18.1"
}

@Suppress("UnstableApiUsage")
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        intellijPlatform {
            defaultRepositories()
        }
    }
}
```

- [ ] **Step 2: Create `build.gradle.kts`**

```kotlin
import org.jetbrains.intellij.platform.gradle.TestFrameworkType

plugins {
    id("java")
    id("org.jetbrains.intellij.platform")
}

group = "com.example.oauthplugin"
version = "1.0.0"

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity("2024.2.6")
        testFramework(TestFrameworkType.Platform)
    }

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.10.2")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks {
    test {
        useJUnitPlatform()
    }
}

intellijPlatform {
    pluginConfiguration {
        id.set("com.example.oauthplugin")
        name.set("OAuth Sample Plugin")
        version.set(project.version.toString())
        ideaVersion {
            sinceBuild.set("242")
        }
    }
}
```

- [ ] **Step 3: Create `gradle.properties`**

```properties
org.gradle.configuration-cache=true
org.gradle.caching=true
```

- [ ] **Step 4: Create `.gitignore`**

```
.gradle/
build/
out/
.idea/
*.iml
.intellijPlatform/
```

- [ ] **Step 5: Create the minimal `src/main/resources/META-INF/plugin.xml`**

```xml
<idea-plugin>
    <id>com.example.oauthplugin</id>
    <name>OAuth Sample Plugin</name>
    <vendor email="support@example.com" url="https://example.com">Example</vendor>
    <description><![CDATA[
        Sample IntelliJ plugin demonstrating OAuth 2.0 Authorization Code + PKCE login,
        application-level token storage via PasswordSafe, and authenticated API calls.
    ]]></description>

    <depends>com.intellij.modules.platform</depends>

    <extensions defaultExtensionNs="com.intellij">
    </extensions>

    <actions>
    </actions>
</idea-plugin>
```

- [ ] **Step 6: Generate the Gradle wrapper**

The IntelliJ Platform Gradle Plugin 2.16.0 requires Gradle 9.0+ (confirmed by
running the build below against Gradle 8.10 first: it fails fast with
`IntelliJ Platform Gradle Plugin requires Gradle Gradle 9.0.0 and higher`).
Use Gradle 9.5.0.

Run: `gradle wrapper --gradle-version 9.5.0 --distribution-type bin`

Expected: creates `gradlew`, `gradlew.bat`, and `gradle/wrapper/gradle-wrapper.jar` + `gradle-wrapper.properties`.

If no system `gradle` binary is available, download the wrapper files directly instead:

```bash
curl -sL -o gradle/wrapper/gradle-wrapper.jar https://raw.githubusercontent.com/gradle/gradle/v9.5.0/gradle/wrapper/gradle-wrapper.jar
curl -sL -o gradlew https://raw.githubusercontent.com/gradle/gradle/v9.5.0/gradlew
curl -sL -o gradlew.bat https://raw.githubusercontent.com/gradle/gradle/v9.5.0/gradlew.bat
chmod +x gradlew
```

and hand-write `gradle/wrapper/gradle-wrapper.properties`:

```properties
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-9.5.0-bin.zip
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
```

- [ ] **Step 7: Verify the empty plugin project builds**

Run: `./gradlew build --console=plain` (Windows: `gradlew.bat build --console=plain`)

Expected: `BUILD SUCCESSFUL`. This resolves the IntelliJ Platform dependency for the first time, which downloads the full IDE distribution — allow several minutes on a cold cache.

- [ ] **Step 8: Commit**

```bash
git add settings.gradle.kts build.gradle.kts gradle.properties .gitignore gradlew gradlew.bat gradle/ src/main/resources/META-INF/plugin.xml
git commit -m "Scaffold buildable Gradle project for OAuth sample plugin"
```

---

### Task 2: `AuthService` + PKCE/URL unit tests (TDD)

**Files:**
- Create: `src/test/java/com/example/oauthplugin/auth/AuthServiceCryptoTest.java`
- Create: `src/main/java/com/example/oauthplugin/auth/AuthService.java`

**Interfaces:**
- Produces:
  - `AuthService` — `@Service(Service.Level.APP)` public final class.
    - `CompletableFuture<Void> login()`
    - `void logout()`
    - `boolean isLoggedIn()`
    - `String getValidAccessToken()` (throws `AuthService.NotAuthenticatedException`)
    - `void invalidateSession()`
    - package-private `static String generateCodeVerifier()`
    - package-private `static String deriveCodeChallenge(String codeVerifier)`
    - package-private `static String generateState()`
    - package-private `static String buildAuthorizationUrl(String redirectUri, String state, String codeChallenge)`
    - package-private `static Map<String, String> parseQuery(String rawQuery)`
    - `public static class AuthException extends RuntimeException`
    - `public static class NotAuthenticatedException extends RuntimeException`

- [ ] **Step 1: Write the failing tests**

Create `src/test/java/com/example/oauthplugin/auth/AuthServiceCryptoTest.java`:

```java
package com.example.oauthplugin.auth;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceCryptoTest {

    private static final Pattern BASE64URL_NO_PADDING = Pattern.compile("^[A-Za-z0-9_-]+$");

    @Test
    void generateCodeVerifier_isBase64UrlNoPaddingAndRfcLengthCompliant() {
        String verifier = AuthService.generateCodeVerifier();

        assertTrue(BASE64URL_NO_PADDING.matcher(verifier).matches(),
                "verifier must be base64url with no padding characters");
        // RFC 7636 requires the verifier to be 43-128 characters long.
        assertTrue(verifier.length() >= 43 && verifier.length() <= 128,
                "verifier length must be within RFC 7636 bounds, was " + verifier.length());
    }

    @Test
    void generateCodeVerifier_isRandomAcrossCalls() {
        String first = AuthService.generateCodeVerifier();
        String second = AuthService.generateCodeVerifier();

        assertTrue(!first.equals(second), "two generated verifiers must not collide");
    }

    @Test
    void deriveCodeChallenge_matchesRfc7636AppendixBTestVector() {
        // RFC 7636 Appendix B worked example.
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assertEquals(expectedChallenge, AuthService.deriveCodeChallenge(verifier));
    }

    @Test
    void generateState_isBase64UrlNoPaddingAndNonEmpty() {
        String state = AuthService.generateState();

        assertTrue(BASE64URL_NO_PADDING.matcher(state).matches(),
                "state must be base64url with no padding characters");
        assertTrue(state.length() > 0);
    }

    @Test
    void buildAuthorizationUrl_containsAllRequiredParamsCorrectlyEncoded() {
        String url = AuthService.buildAuthorizationUrl(
                "http://127.0.0.1:38271/callback",
                "state-value with spaces",
                "challenge-value");

        assertTrue(url.startsWith("https://provider.example.com/oauth/authorize?"));
        assertTrue(url.contains("response_type=code"));
        assertTrue(url.contains("client_id=your-client-id"));
        assertTrue(url.contains("redirect_uri=" + java.net.URLEncoder.encode(
                "http://127.0.0.1:38271/callback", java.nio.charset.StandardCharsets.UTF_8)));
        assertTrue(url.contains("scope=" + java.net.URLEncoder.encode(
                "openid profile offline_access", java.nio.charset.StandardCharsets.UTF_8)));
        assertTrue(url.contains("state=" + java.net.URLEncoder.encode(
                "state-value with spaces", java.nio.charset.StandardCharsets.UTF_8)));
        assertTrue(url.contains("code_challenge=challenge-value"));
        assertTrue(url.contains("code_challenge_method=S256"));
    }

    @Test
    void parseQuery_decodesKeyValuePairs() {
        Map<String, String> result = AuthService.parseQuery("code=abc123&state=xyz%20789");

        assertEquals("abc123", result.get("code"));
        assertEquals("xyz 789", result.get("state"));
    }

    @Test
    void parseQuery_handlesNullAndEmptyInput() {
        assertTrue(AuthService.parseQuery(null).isEmpty());
        assertTrue(AuthService.parseQuery("").isEmpty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `./gradlew test --tests "com.example.oauthplugin.auth.AuthServiceCryptoTest" --console=plain`

Expected: compilation failure — `AuthService` does not exist yet.

- [ ] **Step 3: Create `src/main/java/com/example/oauthplugin/auth/AuthService.java`**

```java
package com.example.oauthplugin.auth;

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
 * lazily as a singleton via the {@code @Service} annotation, no plugin.xml
 * registration required on 2020.1+ targets.
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
            // TODO: if the target provider supports a revocation endpoint,
            // call it here before clearing local tokens.
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

    static String buildAuthorizationUrl(String redirectUri, String state, String codeChallenge) {
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

    static String generateCodeVerifier() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String deriveCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed available on every JDK; this is unreachable in practice.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    static String generateState() {
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

    static Map<String, String> parseQuery(String rawQuery) {
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `./gradlew test --tests "com.example.oauthplugin.auth.AuthServiceCryptoTest" --console=plain`

Expected: `BUILD SUCCESSFUL`, all 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/example/oauthplugin/auth/AuthService.java src/test/java/com/example/oauthplugin/auth/AuthServiceCryptoTest.java
git commit -m "Add AuthService (PKCE OAuth login/refresh/logout) with crypto/URL unit tests"
```

---

### Task 3: `AuthenticatedApiClient`

**Files:**
- Create: `src/main/java/com/example/oauthplugin/auth/AuthenticatedApiClient.java`

**Interfaces:**
- Consumes: `AuthService#getValidAccessToken()`, `AuthService#invalidateSession()`, `AuthService.NotAuthenticatedException`.
- Produces: `AuthenticatedApiClient` with `public HttpResponse<String> send(HttpRequest.Builder requestBuilder)`.

- [ ] **Step 1: Create the class**

```java
package com.example.oauthplugin.auth;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Wraps outgoing API calls with bearer-token injection and a single
 * bounded refresh-then-fail retry on 401. Never loops.
 */
public final class AuthenticatedApiClient {

    private final AuthService authService;
    private final HttpClient httpClient;

    public AuthenticatedApiClient(AuthService authService) {
        this(authService, HttpClient.newHttpClient());
    }

    AuthenticatedApiClient(AuthService authService, HttpClient httpClient) {
        this.authService = authService;
        this.httpClient = httpClient;
    }

    /**
     * Sends the given request with a fresh bearer token attached. On a 401
     * response, invalidates the local session and throws
     * {@link AuthService.NotAuthenticatedException} rather than retrying in
     * a loop. Call this off the EDT - it performs blocking network I/O and
     * may perform a blocking token refresh first.
     */
    public HttpResponse<String> send(HttpRequest.Builder requestBuilder) throws IOException, InterruptedException {
        String token = authService.getValidAccessToken();
        HttpRequest request = requestBuilder
                .header("Authorization", "Bearer " + token)
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 401) {
            // Token was revoked server-side unexpectedly - force full re-auth, don't loop.
            authService.invalidateSession();
            throw new AuthService.NotAuthenticatedException(
                    "Server rejected the access token (401); session invalidated. Sign in again.");
        }

        return response;
    }
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `./gradlew compileJava --console=plain`

Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add src/main/java/com/example/oauthplugin/auth/AuthenticatedApiClient.java
git commit -m "Add AuthenticatedApiClient with bounded 401 handling"
```

---

### Task 4: Sign In / Sign Out actions

**Files:**
- Create: `src/main/java/com/example/oauthplugin/actions/LoginAction.java`
- Create: `src/main/java/com/example/oauthplugin/actions/LogoutAction.java`
- Modify: `src/main/resources/META-INF/plugin.xml`

**Interfaces:**
- Consumes: `AuthService#login()`, `AuthService#logout()`, `AuthService#isLoggedIn()` via `ApplicationManager.getApplication().getService(AuthService.class)`.
- Produces: two `AnAction` implementations registered under a "OAuth Sample" group in the Tools menu.

- [ ] **Step 1: Create `LoginAction.java`**

```java
package com.example.oauthplugin.actions;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.ActionUpdateThread;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.application.ApplicationManager;
import org.jetbrains.annotations.NotNull;

public final class LoginAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);

        authService.login().whenComplete((result, throwable) ->
                ApplicationManager.getApplication().invokeLater(() -> {
                    NotificationGroupManager notifications = NotificationGroupManager.getInstance();
                    if (throwable != null) {
                        notifications.getNotificationGroup("OAuth Sample Plugin")
                                .createNotification("Sign-in failed", throwable.getMessage(), NotificationType.ERROR)
                                .notify(e.getProject());
                    } else {
                        notifications.getNotificationGroup("OAuth Sample Plugin")
                                .createNotification("Signed in successfully", NotificationType.INFORMATION)
                                .notify(e.getProject());
                    }
                }));
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        e.getPresentation().setEnabled(!authService.isLoggedIn());
    }

    @Override
    public @NotNull ActionUpdateThread getActionUpdateThread() {
        return ActionUpdateThread.BGT;
    }
}
```

- [ ] **Step 2: Create `LogoutAction.java`**

```java
package com.example.oauthplugin.actions;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.ActionUpdateThread;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.application.ApplicationManager;
import org.jetbrains.annotations.NotNull;

public final class LogoutAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        authService.logout();

        NotificationGroupManager.getInstance()
                .getNotificationGroup("OAuth Sample Plugin")
                .createNotification("Signed out", NotificationType.INFORMATION)
                .notify(e.getProject());
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        e.getPresentation().setEnabled(authService.isLoggedIn());
    }

    @Override
    public @NotNull ActionUpdateThread getActionUpdateThread() {
        return ActionUpdateThread.BGT;
    }
}
```

- [ ] **Step 3: Register the notification group, actions, and group in `plugin.xml`**

Replace the empty `<extensions>` and `<actions>` blocks in `src/main/resources/META-INF/plugin.xml` with:

```xml
    <extensions defaultExtensionNs="com.intellij">
        <notificationGroup id="OAuth Sample Plugin" displayType="BALLOON"/>
    </extensions>

    <actions>
        <group id="com.example.oauthplugin.AuthActionsGroup" text="OAuth Sample" popup="true">
            <add-to-group group-id="ToolsMenu" anchor="last"/>
            <action id="com.example.oauthplugin.LoginAction"
                    class="com.example.oauthplugin.actions.LoginAction"
                    text="Sign In..." description="Sign in via OAuth"/>
            <action id="com.example.oauthplugin.LogoutAction"
                    class="com.example.oauthplugin.actions.LogoutAction"
                    text="Sign Out" description="Sign out and clear local tokens"/>
        </group>
    </actions>
```

- [ ] **Step 4: Build to verify it compiles and the plugin descriptor is valid**

Run: `./gradlew build --console=plain`

Expected: `BUILD SUCCESSFUL` (the `verifyPluginProjectConfiguration`/`patchPluginXml` tasks validate the descriptor as part of `build`).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/example/oauthplugin/actions/ src/main/resources/META-INF/plugin.xml
git commit -m "Add Sign In / Sign Out actions under Tools menu"
```

---

### Task 5: Settings page (`Configurable`)

**Files:**
- Create: `src/main/java/com/example/oauthplugin/settings/OAuthSettingsComponent.java`
- Create: `src/main/java/com/example/oauthplugin/settings/OAuthConfigurable.java`
- Modify: `src/main/resources/META-INF/plugin.xml`

**Interfaces:**
- Consumes: `AuthService#isLoggedIn()`, `#login()`, `#logout()`.
- Produces: `OAuthSettingsComponent` (Swing panel: state label + one button whose label toggles Sign In/Sign Out) and `OAuthConfigurable` (`Configurable`) registered as an application-level settings page.

- [ ] **Step 1: Create `OAuthSettingsComponent.java`**

```java
package com.example.oauthplugin.settings;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.util.ui.FormBuilder;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** Swing panel shown on the OAuth Sample Plugin settings page. */
public final class OAuthSettingsComponent {

    private final JPanel panel;
    private final JLabel statusLabel = new JLabel();
    private final JButton actionButton = new JButton();

    public OAuthSettingsComponent() {
        actionButton.addActionListener(e -> {
            AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
            if (authService.isLoggedIn()) {
                authService.logout();
                refresh();
            } else {
                actionButton.setEnabled(false);
                authService.login().whenComplete((result, throwable) ->
                        ApplicationManager.getApplication().invokeLater(this::refresh));
            }
        });

        panel = FormBuilder.createFormBuilder()
                .addComponent(statusLabel)
                .addComponent(actionButton)
                .addComponentFillVertically(new JPanel(), 0)
                .getPanel();

        refresh();
    }

    public JPanel getPanel() {
        return panel;
    }

    public void refresh() {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        boolean loggedIn = authService.isLoggedIn();
        statusLabel.setText(loggedIn ? "Signed in" : "Not signed in");
        actionButton.setText(loggedIn ? "Sign Out" : "Sign In...");
        actionButton.setEnabled(true);
    }
}
```

- [ ] **Step 2: Create `OAuthConfigurable.java`**

```java
package com.example.oauthplugin.settings;

import com.intellij.openapi.options.Configurable;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JComponent;

public final class OAuthConfigurable implements Configurable {

    private OAuthSettingsComponent component;

    @Nls(capitalization = Nls.Capitalization.Title)
    @Override
    public String getDisplayName() {
        return "OAuth Sample Plugin";
    }

    @Override
    public @Nullable JComponent createComponent() {
        component = new OAuthSettingsComponent();
        return component.getPanel();
    }

    @Override
    public boolean isModified() {
        // Purely a login-state viewer/actuator; nothing to persist as settings.
        return false;
    }

    @Override
    public void apply() {
        // No persisted settings fields to apply.
    }

    @Override
    public void reset() {
        if (component != null) {
            component.refresh();
        }
    }

    @Override
    public void disposeUIResources() {
        component = null;
    }
}
```

- [ ] **Step 3: Register the `Configurable` in `plugin.xml`**

Add inside the existing `<extensions defaultExtensionNs="com.intellij">` block (alongside `notificationGroup`):

```xml
        <applicationConfigurable
                parentId="tools"
                instance="com.example.oauthplugin.settings.OAuthConfigurable"
                id="com.example.oauthplugin.settings.OAuthConfigurable"
                displayName="OAuth Sample Plugin"/>
```

- [ ] **Step 4: Build to verify**

Run: `./gradlew build --console=plain`

Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/example/oauthplugin/settings/ src/main/resources/META-INF/plugin.xml
git commit -m "Add OAuth settings page (sign-in state + toggle button)"
```

---

### Task 6: Status bar widget

**Files:**
- Create: `src/main/java/com/example/oauthplugin/statusbar/AuthStatusBarWidget.java`
- Create: `src/main/java/com/example/oauthplugin/statusbar/AuthStatusBarWidgetFactory.java`
- Modify: `src/main/resources/META-INF/plugin.xml`

**Interfaces:**
- Consumes: `AuthService#isLoggedIn()`.
- Produces: `AuthStatusBarWidgetFactory` (`StatusBarWidgetFactory`) registered so IntelliJ shows an "OAuth Sample" entry in the status bar widgets list; `AuthStatusBarWidget` (`StatusBarWidget.TextPresentation`) showing "Signed in" / "Not signed in".

- [ ] **Step 1: Create `AuthStatusBarWidget.java`**

```java
package com.example.oauthplugin.statusbar;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.wm.StatusBar;
import com.intellij.openapi.wm.StatusBarWidget;
import com.intellij.util.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.awt.event.MouseEvent;

public final class AuthStatusBarWidget implements StatusBarWidget, StatusBarWidget.TextPresentation {

    public static final String ID = "com.example.oauthplugin.AuthStatusBarWidget";

    private StatusBar statusBar;

    @Override
    public @NotNull String ID() {
        return ID;
    }

    @Override
    public void install(@NotNull StatusBar statusBar) {
        this.statusBar = statusBar;
    }

    @Override
    public void dispose() {
        statusBar = null;
    }

    @Override
    public WidgetPresentation getPresentation() {
        return this;
    }

    @Override
    public @NotNull String getText() {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        return authService.isLoggedIn() ? "Signed in" : "Not signed in";
    }

    @Override
    public float getAlignment() {
        return 0f;
    }

    @Override
    public @Nullable String getTooltipText() {
        return "OAuth Sample Plugin login state";
    }

    @Override
    public @Nullable Consumer<MouseEvent> getClickConsumer() {
        return null;
    }

    /** Call after login/logout completes so the widget text refreshes immediately. */
    public void refresh() {
        if (statusBar != null) {
            statusBar.updateWidget(ID);
        }
    }
}
```

- [ ] **Step 2: Create `AuthStatusBarWidgetFactory.java`**

```java
package com.example.oauthplugin.statusbar;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.StatusBar;
import com.intellij.openapi.wm.StatusBarWidget;
import com.intellij.openapi.wm.StatusBarWidgetFactory;
import org.jetbrains.annotations.NotNull;

public final class AuthStatusBarWidgetFactory implements StatusBarWidgetFactory {

    @Override
    public @NotNull String getId() {
        return AuthStatusBarWidget.ID;
    }

    @Override
    public @NotNull String getDisplayName() {
        return "OAuth Sample Plugin";
    }

    @Override
    public boolean isAvailable(@NotNull Project project) {
        return true;
    }

    @Override
    public @NotNull StatusBarWidget createWidget(@NotNull Project project) {
        return new AuthStatusBarWidget();
    }

    @Override
    public void disposeWidget(@NotNull StatusBarWidget widget) {
        widget.dispose();
    }

    @Override
    public boolean canBeEnabledOn(@NotNull StatusBar statusBar) {
        return true;
    }
}
```

- [ ] **Step 3: Register the factory in `plugin.xml`**

Add inside `<extensions defaultExtensionNs="com.intellij">`:

```xml
        <statusBarWidgetFactory
                id="com.example.oauthplugin.AuthStatusBarWidget"
                implementation="com.example.oauthplugin.statusbar.AuthStatusBarWidgetFactory"/>
```

- [ ] **Step 4: Build to verify**

Run: `./gradlew build --console=plain`

Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/example/oauthplugin/statusbar/ src/main/resources/META-INF/plugin.xml
git commit -m "Add status bar widget showing OAuth login state"
```

---

### Task 7: README and final verification

**Files:**
- Create: `README.md`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Create `README.md`**

```markdown
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
```

- [ ] **Step 2: Full clean build + test run**

Run: `./gradlew clean build --console=plain`

Expected: `BUILD SUCCESSFUL`, all tests pass, `build/distributions/*.zip` plugin artifact produced.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Add README with build/run/test instructions"
```
