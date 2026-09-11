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
        this(authService, authService.getHttpClient());
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
