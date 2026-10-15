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
import com.intellij.util.net.JdkProxyProvider;

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
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
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
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TOKEN_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    // Routes token exchange/refresh calls through whatever proxy the user has
    // configured in the IDE (Settings > Appearance & Behavior > System Settings
    // > HTTP Proxy), instead of only the JVM's system-property defaults.
    private final HttpClient httpClient = HttpClient.newBuilder()
            .proxy(JdkProxyProvider.getInstance().getProxySelector())
            .authenticator(JdkProxyProvider.getInstance().getAuthenticator())
            .connectTimeout(CONNECT_TIMEOUT)
            .build();
    private final Gson gson = new Gson();
    private final ExecutorService authExecutor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "oauth-auth-service");
                t.setDaemon(true);
                return t;
            });

    // Guards against two concurrent login attempts racing each other.
    private final AtomicReference<CompletableFuture<Void>> inFlightLogin = new AtomicReference<>();

    // The pending browser-callback wait for the current login attempt, if
    // any; cancelLogin() cancels this to let a caller abort the wait early.
    private final AtomicReference<CompletableFuture<String>> inFlightCodeFuture = new AtomicReference<>();

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

    /**
     * Cancels the current login attempt's wait for the browser callback, if
     * one is in progress. No-op otherwise. Lets a "waiting for sign-in..."
     * progress UI offer a working Cancel button instead of forcing the user
     * to wait out the full login timeout.
     */
    public void cancelLogin() {
        CompletableFuture<String> codeFuture = inFlightCodeFuture.get();
        if (codeFuture != null) {
            codeFuture.cancel(true);
        }
    }

    /**
     * Clears local session state. Safe to call from the EDT; the actual
     * clearing happens on the auth executor. The returned future completes
     * once tokens have actually been cleared.
     */
    public CompletableFuture<Void> logout() {
        CompletableFuture<Void> future = new CompletableFuture<>();
        authExecutor.submit(() -> {
            try {
                // TODO: if the target provider supports a revocation endpoint,
                // call it here before clearing local tokens.
                clearStoredTokens();
                LOG.info("User signed out; local tokens cleared.");
                future.complete(null);
            } catch (Exception e) {
                future.completeExceptionally(e);
            }
        });
        return future;
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
     *
     * The check-and-refresh is run on the single-thread auth executor - the
     * same one login() uses - so a refresh can never race another refresh or
     * a fresh login and clobber a token a concurrent caller just stored.
     */
    public String getValidAccessToken() {
        try {
            return authExecutor.submit(this::getValidAccessTokenOnAuthExecutor).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthException("Interrupted while obtaining access token.", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new AuthException("Failed to obtain access token.", cause);
        }
    }

    private String getValidAccessTokenOnAuthExecutor() {
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

    /**
     * Forces the next getValidAccessToken() call to require a fresh login.
     * Safe to call from any thread: the actual clearing is serialized onto
     * the same auth executor every other token mutation uses, so this can't
     * interleave with an in-flight login/refresh's own credential writes.
     */
    public void invalidateSession() {
        authExecutor.submit(this::clearStoredTokens);
    }

    /** The HttpClient this service already maintains, for reuse by API callers. */
    HttpClient getHttpClient() {
        return httpClient;
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
            inFlightCodeFuture.set(codeFuture);
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
            inFlightCodeFuture.set(null);
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
            if (returnedState == null || !returnedState.equals(expectedState)) {
                message = "Security check failed. You can close this window.";
                codeFuture.completeExceptionally(new AuthException("OAuth state mismatch - possible CSRF attempt."));
            } else if (error != null) {
                message = "Authentication failed: " + escapeHtml(error) + ". You can close this window.";
                codeFuture.completeExceptionally(new AuthException("Provider returned error: " + escapeHtml(error)));
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
                    .timeout(TOKEN_REQUEST_TIMEOUT)
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

    /** Escapes text reflected into the loopback callback's HTML response. */
    static String escapeHtml(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
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
