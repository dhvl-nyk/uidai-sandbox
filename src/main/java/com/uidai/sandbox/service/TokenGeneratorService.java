package com.uidai.sandbox.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.UUID;

@Service
public class TokenGeneratorService {

    private final RSAPrivateKey sandboxPrivateKey;
    private final String sandboxKeyId = "sandbox-key-v1";

    public TokenGeneratorService() throws Exception {
        // MOCK: Generate a local RSA key pair for the Sandbox signing process
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        this.sandboxPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    public String generateSandboxSessionToken(String subject, String fullName) throws JOSEException {
        // Create the Sandbox Claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .claim("full_name", fullName)
                .claim("assurance_level", "HIGH")
                .issuer("https://sandbox.uidai.gov.in")
                .expirationTime(new Date(new Date().getTime() + 3600 * 1000)) // 1 hour expiry
                .jwtID(UUID.randomUUID().toString())
                .build();

        // Create the header with Sandbox's kid
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(sandboxKeyId)
                .type(JOSEObjectType.JWT)
                .build();

        // Sign and serialize
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(sandboxPrivateKey));

        return signedJWT.serialize();
    }
}