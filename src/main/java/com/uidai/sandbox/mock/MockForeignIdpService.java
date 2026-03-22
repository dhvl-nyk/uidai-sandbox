package com.uidai.sandbox.mock;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class MockForeignIdpService {

    private final RSAKey rsaJWK;
    private final RSAPrivateKey privateKey;
    private final String KEY_ID = "foreign-signing-key-1";

    public MockForeignIdpService() throws Exception {
        // Generate an RSA Key Pair for the Mock Foreign IdP
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // Build the JWK representation of the public key
        rsaJWK = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }

    // 1. Serve the Public Key Set (JWKS)
    public Map<String, Object> getJwks() {
        return new JWKSet(rsaJWK.toPublicJWK()).toJSONObject();
    }

    // 2. Generate a Mock "Foreign Token" to use for testing
    public String generateMockForeignToken() throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("eu-usr-88372")
                .issuer("http://localhost:8080/mock-idp")
                .claim("given_name", "Elena")
                .claim("family_name", "Rostova")
                .claim("nationality", "DEU")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(KEY_ID)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(privateKey));

        return signedJWT.serialize();
    }
}