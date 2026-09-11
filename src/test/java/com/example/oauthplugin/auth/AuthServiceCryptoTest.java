package com.example.oauthplugin.auth;

import org.junit.jupiter.api.Test;

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

    @Test
    void escapeHtml_neutralizesScriptInjection() {
        String malicious = "<script>alert(1)</script>";

        String escaped = AuthService.escapeHtml(malicious);

        assertTrue(!escaped.contains("<script>"), "escaped output must not contain a raw <script> tag");
        assertEquals("&lt;script&gt;alert(1)&lt;/script&gt;", escaped);
    }

    @Test
    void escapeHtml_escapesAllHtmlSpecialCharacters() {
        assertEquals("&amp;&lt;&gt;&quot;&#39;", AuthService.escapeHtml("&<>\"'"));
    }
}
