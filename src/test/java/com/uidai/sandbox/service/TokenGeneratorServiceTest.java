package com.uidai.sandbox.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("TokenGeneratorService")
class TokenGeneratorServiceTest {

    private TokenGeneratorService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new TokenGeneratorService();
    }

    @Test
    @DisplayName("generateSandboxSessionToken() returns a well-formed JWT")
    void generate_returnsWellFormedJwt() throws Exception {
        String token = service.generateSandboxSessionToken("test-subject", "Jane Doe");
        assertThat(token.split("\\.")).hasSize(3);
        SignedJWT.parse(token); // must not throw
    }

    @Test
    @DisplayName("generateSandboxSessionToken() uses RS256")
    void generate_usesRs256() throws Exception {
        String token = service.generateSandboxSessionToken("sub", "Name");
        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    @DisplayName("generateSandboxSessionToken() header uses kid 'sandbox-key-v1'")
    void generate_hasCorrectKid() throws Exception {
        String token = service.generateSandboxSessionToken("sub", "Name");
        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("sandbox-key-v1");
    }

    @Test
    @DisplayName("generateSandboxSessionToken() maps subject correctly")
    void generate_mapsSubject() throws Exception {
        String token = service.generateSandboxSessionToken("eu-usr-88372", "Elena Rostova");
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo("eu-usr-88372");
    }

    @Test
    @DisplayName("generateSandboxSessionToken() maps full_name correctly")
    void generate_mapsFullName() throws Exception {
        String token = service.generateSandboxSessionToken("eu-usr-88372", "Elena Rostova");
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
        assertThat(claims.getStringClaim("full_name")).isEqualTo("Elena Rostova");
    }

    @Test
    @DisplayName("generateSandboxSessionToken() sets issuer to UIDAI sandbox URL")
    void generate_hasCorrectIssuer() throws Exception {
        String token = service.generateSandboxSessionToken("sub", "Name");
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://sandbox.uidai.gov.in");
    }

    @Test
    @DisplayName("generateSandboxSessionToken() sets assurance_level to HIGH")
    void generate_hasHighAssuranceLevel() throws Exception {
        String token = service.generateSandboxSessionToken("sub", "Name");
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
        assertThat(claims.getStringClaim("assurance_level")).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("generateSandboxSessionToken() sets expiry ~1 hour in the future")
    void generate_expiresInOneHour() throws Exception {
        long before = System.currentTimeMillis();
        String token = service.generateSandboxSessionToken("sub", "Name");
        long after = System.currentTimeMillis();

        Date exp = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime();

        assertThat(exp.getTime()).isGreaterThan(before + 3590_000L);
        assertThat(exp.getTime()).isLessThan(after  + 3610_000L);
    }

    @Test
    @DisplayName("generateSandboxSessionToken() includes a unique jti per call")
    void generate_hasUniqueJti() throws Exception {
        String t1 = service.generateSandboxSessionToken("sub", "Name");
        String t2 = service.generateSandboxSessionToken("sub", "Name");
        String jti1 = SignedJWT.parse(t1).getJWTClaimsSet().getJWTID();
        String jti2 = SignedJWT.parse(t2).getJWTClaimsSet().getJWTID();
        assertThat(jti1).isNotEqualTo(jti2);
    }

    @Test
    @DisplayName("generateSandboxSessionToken() handles empty full name gracefully")
    void generate_handlesEmptyName() throws Exception {
        String token = service.generateSandboxSessionToken("sub", "");
        JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
        assertThat(claims.getStringClaim("full_name")).isEmpty();
    }
}
