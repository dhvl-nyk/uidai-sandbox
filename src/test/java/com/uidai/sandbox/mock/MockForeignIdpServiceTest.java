package com.uidai.sandbox.mock;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MockForeignIdpService")
class MockForeignIdpServiceTest {

    private MockForeignIdpService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new MockForeignIdpService();
    }

    // ── JWKS endpoint ────────────────────────────────────────────────────────

    @Test
    @DisplayName("getJwks() exposes exactly one RSA public key")
    void getJwks_containsOneRsaKey() throws Exception {
        Map<String, Object> jwks = service.getJwks();
        JWKSet parsed = JWKSet.parse(jwks);
        assertThat(parsed.getKeys()).hasSize(1);
        assertThat(parsed.getKeys().get(0)).isInstanceOf(RSAKey.class);
    }

    @Test
    @DisplayName("generateMockForeignToken() claims contain expected identity fields")
    void generateToken_containsExpectedClaims() throws Exception {
        String token = service.generateMockForeignToken();
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();

        assertThat(claims.getSubject()).isEqualTo("eu-usr-88372");
        assertThat(claims.getIssuer()).isEqualTo("http://localhost:8080/mock-idp");
        assertThat(claims.getStringClaim("given_name")).isEqualTo("Elena");
        assertThat(claims.getStringClaim("family_name")).isEqualTo("Rostova");
        assertThat(claims.getStringClaim("nationality")).isEqualTo("DEU");
    }
}
