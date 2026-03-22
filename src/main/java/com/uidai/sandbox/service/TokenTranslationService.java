package com.uidai.sandbox.service;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URL;

@Service
public class TokenTranslationService {

    private final TokenGeneratorService tokenGeneratorService;
    private final String jwksUrlStr;

    // Lazily initialized on first use — avoids a startup race condition where
    // RemoteJWKSet tries to fetch the JWKS before the embedded HTTP server is
    // ready to serve /mock-idp/.well-known/jwks.json, resulting in an empty
    // cached key set that can never verify any token.
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public TokenTranslationService(
            TokenGeneratorService tokenGeneratorService,
            @Value("${foreign.idp.jwks-url}") String jwksUrlStr) {

        this.tokenGeneratorService = tokenGeneratorService;
        this.jwksUrlStr = jwksUrlStr;
    }

    private ConfigurableJWTProcessor<SecurityContext> getProcessor() throws Exception {
        if (jwtProcessor == null) {
            synchronized (this) {
                if (jwtProcessor == null) {
                    // RemoteJWKSet provides built-in caching and automatic re-fetch on key
                    // rotation: if a kid is not found in the cache, Nimbus re-fetches the
                    // JWKS endpoint before failing. A brief network outage won't fail every
                    // request — the cached key set continues to serve until the TTL expires.
                    URL jwksUrl = new URL(jwksUrlStr);
                    JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(jwksUrl);

                    JWSVerificationKeySelector<SecurityContext> keySelector =
                            new JWSVerificationKeySelector<>(
                                    com.nimbusds.jose.JWSAlgorithm.RS256, keySource);

                    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
                    processor.setJWSKeySelector(keySelector);
                    jwtProcessor = processor;
                }
            }
        }
        return jwtProcessor;
    }

    public String exchangeToken(String foreignJwtString) {
        try {
            // Verify token dynamically — key resolved from JWKS via kid in JWT header
            JWTClaimsSet foreignClaims = getProcessor().process(foreignJwtString, null);

            String normalizedFullName = normalizeName(
                    foreignClaims.getStringClaim("given_name"),
                    foreignClaims.getStringClaim("family_name")
            );
            String subjectId = foreignClaims.getSubject();

            return tokenGeneratorService.generateSandboxSessionToken(subjectId, normalizedFullName);

        } catch (Exception e) {
            throw new SecurityException("Foreign token verification failed: " + e.getMessage(), e);
        }
    }

    private String normalizeName(String givenName, String familyName) {
        if (givenName == null) givenName = "";
        if (familyName == null) familyName = "";
        return (givenName + " " + familyName).trim();
    }
}
