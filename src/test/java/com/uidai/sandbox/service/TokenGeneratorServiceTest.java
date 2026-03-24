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
    @DisplayName("generateSandboxSessionToken() header uses kid 'sandbox-key-v1'")
    void generate_hasCorrectKid() throws Exception {
        String token = service.generateSandboxSessionToken("sub", "Name");
        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("sandbox-key-v1");
    }
}
