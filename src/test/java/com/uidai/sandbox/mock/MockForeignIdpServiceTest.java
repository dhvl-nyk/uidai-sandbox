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
    @DisplayName("getJwks() returns a JWKS map with a 'keys' array")
    void getJwks_returnsKeysArray() {
        Map<String, Object> jwks = service.getJwks();
        assertThat(jwks).containsKey("keys");
        assertThat(jwks.get("keys")).isInstanceOf(java.util.List.class);
    }

    @Test
    @DisplayName("getJwks() exposes exactly one RSA public key")
    void getJwks_containsOneRsaKey() throws Exception {
        Map<String, Object> jwks = service.getJwks();
        JWKSet parsed = JWKSet.parse(jwks);
        assertThat(parsed.getKeys()).hasSize(1);
        assertThat(parsed.getKeys().get(0)).isInstanceOf(RSAKey.class);
    }

    @Test
    @DisplayName("getJwks() does NOT expose the private key material")
    void getJwks_doesNotExposePrivateKey() throws Exception {
        Map<String, Object> jwks = service.getJwks();
        JWKSet parsed = JWKSet.parse(jwks);
        RSAKey rsaKey = (RSAKey) parsed.getKeys().get(0);
        assertThat(rsaKey.isPrivate()).isFalse();
    }

    @Test
    @DisplayName("getJwks() key uses kid 'foreign-signing-key-1'")
    void getJwks_hasExpectedKeyId() throws Exception {
        Map<String, Object> jwks = service.getJwks();
        JWKSet parsed = JWKSet.parse(jwks);
        assertThat(parsed.getKeys().get(0).getKeyID()).isEqualTo("foreign-signing-key-1");
    }

    // ── Token generation ─────────────────────────────────────────────────────

    @Test
    @DisplayName("generateMockForeignToken() returns a parseable three-part JWT")
    void generateToken_isWellFormedJwt() throws Exception {
        String token = service.generateMockForeignToken();
        assertThat(token.split("\\.")).hasSize(3);
        // Should parse without throwing
        SignedJWT.parse(token);
    }

    @Test
    @DisplayName("generateMockForeignToken() uses RS256 algorithm")
    void generateToken_usesRs256() throws Exception {
        String token = service.generateMockForeignToken();
        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    @DisplayName("generateMockForeignToken() header carries the correct kid")
    void generateToken_headerHasCorrectKid() throws Exception {
        String token = service.generateMockForeignToken();
        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("foreign-signing-key-1");
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

    @Test
    @DisplayName("generateMockForeignToken() sets expiry ~60 seconds in the future")
    void generateToken_expiresInApproximately60Seconds() throws Exception {
        long before = System.currentTimeMillis();
        String token = service.generateMockForeignToken();
        long after = System.currentTimeMillis();

        Date exp = SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime();
        long expiryMs = exp.getTime();

        assertThat(expiryMs).isGreaterThan(before + 55_000);
        assertThat(expiryMs).isLessThan(after + 65_000);
    }

    @Test
    @DisplayName("generateMockForeignToken() signature is verifiable with the served public key")
    void generateToken_signatureVerifiesAgainstJwks() throws Exception {
        String token = service.generateMockForeignToken();
        SignedJWT jwt = SignedJWT.parse(token);

        // Pull the public key from the JWKS the service serves
        JWKSet jwkSet = JWKSet.parse(service.getJwks());
        RSAKey publicKey = (RSAKey) jwkSet.getKeyByKeyId("foreign-signing-key-1");

        com.nimbusds.jose.crypto.RSASSAVerifier verifier =
                new com.nimbusds.jose.crypto.RSASSAVerifier(publicKey);
        assertThat(jwt.verify(verifier)).isTrue();
    }

    @Test
    @DisplayName("Each service instance generates an independent key pair")
    void differentInstances_haveDifferentKeys() throws Exception {
        MockForeignIdpService other = new MockForeignIdpService();

        JWKSet jwks1 = JWKSet.parse(service.getJwks());
        JWKSet jwks2 = JWKSet.parse(other.getJwks());

        RSAKey key1 = (RSAKey) jwks1.getKeys().get(0);
        RSAKey key2 = (RSAKey) jwks2.getKeys().get(0);

        // Public key moduli should differ across instances
        assertThat(key1.toRSAPublicKey().getModulus())
                .isNotEqualTo(key2.toRSAPublicKey().getModulus());
    }
}
