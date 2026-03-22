package com.uidai.sandbox.service;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.uidai.sandbox.mock.MockForeignIdpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * TokenTranslationService requires a live JWKS URL, so we spin up the full
 * application context on a random port to avoid conflicts with any running app
 * or other test classes. The @LocalServerPort is injected after context startup
 * and used to build the TokenTranslationService pointing at the correct port.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DisplayName("TokenTranslationService")
class TokenTranslationServiceTest {

    @LocalServerPort
    private int port;

    @Autowired
    private MockForeignIdpService mockIdpService;

    @Autowired
    private TokenGeneratorService tokenGeneratorService;

    private TokenTranslationService translationService;

    @BeforeEach
    void setUp() throws Exception {
        // Build a fresh TranslationService pointing at the random port the test
        // server actually started on — avoids hardcoded port 8080 collisions.
        translationService = new TokenTranslationService(
                tokenGeneratorService,
                "http://localhost:" + port + "/mock-idp/.well-known/jwks.json"
        );
    }

    @Test
    @DisplayName("exchangeToken() returns a non-blank JWT string")
    void exchange_returnsJwt() throws Exception {
        String foreignToken = mockIdpService.generateMockForeignToken();
        String result = translationService.exchangeToken(foreignToken);
        assertThat(result).isNotBlank();
        assertThat(result.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("exchangeToken() sandbox token has subject from foreign token")
    void exchange_preservesSubject() throws Exception {
        String foreignToken = mockIdpService.generateMockForeignToken();
        String sandboxToken = translationService.exchangeToken(foreignToken);
        JWTClaimsSet claims = SignedJWT.parse(sandboxToken).getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo("eu-usr-88372");
    }

    @Test
    @DisplayName("exchangeToken() normalizes given_name + family_name into full_name")
    void exchange_normalizesFullName() throws Exception {
        String foreignToken = mockIdpService.generateMockForeignToken();
        String sandboxToken = translationService.exchangeToken(foreignToken);
        JWTClaimsSet claims = SignedJWT.parse(sandboxToken).getJWTClaimsSet();
        assertThat(claims.getStringClaim("full_name")).isEqualTo("Elena Rostova");
    }

    @Test
    @DisplayName("exchangeToken() sandbox token is issued by UIDAI sandbox")
    void exchange_sandboxIssuer() throws Exception {
        String foreignToken = mockIdpService.generateMockForeignToken();
        String sandboxToken = translationService.exchangeToken(foreignToken);
        JWTClaimsSet claims = SignedJWT.parse(sandboxToken).getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://sandbox.uidai.gov.in");
    }

    @Test
    @DisplayName("exchangeToken() sandbox token carries HIGH assurance level")
    void exchange_highAssuranceLevel() throws Exception {
        String foreignToken = mockIdpService.generateMockForeignToken();
        String sandboxToken = translationService.exchangeToken(foreignToken);
        JWTClaimsSet claims = SignedJWT.parse(sandboxToken).getJWTClaimsSet();
        assertThat(claims.getStringClaim("assurance_level")).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("exchangeToken() rejects a tampered token with SecurityException")
    void exchange_rejectsTamperedToken() throws Exception {
        String foreignToken = mockIdpService.generateMockForeignToken();
        String[] parts = foreignToken.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." +
                (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);

        assertThatThrownBy(() -> translationService.exchangeToken(tampered))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Foreign token verification failed");
    }

    @Test
    @DisplayName("exchangeToken() rejects a completely fabricated token")
    void exchange_rejectsFabricatedToken() {
        String fake = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.invalidsignature";
        assertThatThrownBy(() -> translationService.exchangeToken(fake))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("exchangeToken() rejects plaintext (non-JWT) input")
    void exchange_rejectsPlaintext() {
        assertThatThrownBy(() -> translationService.exchangeToken("not-a-jwt"))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    @DisplayName("exchangeToken() rejects null input")
    void exchange_rejectsNull() {
        assertThatThrownBy(() -> translationService.exchangeToken(null))
                .isInstanceOf(Exception.class);
    }
}
