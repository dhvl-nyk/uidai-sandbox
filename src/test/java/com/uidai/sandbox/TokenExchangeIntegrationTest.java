package com.uidai.sandbox;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

// MOCK environment: no real port bound — MockMvc dispatches in-process.
// Safe to run with a live app on 8080 or in parallel with other test classes.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@DisplayName("End-to-End: Full Token Exchange Flow")
class TokenExchangeIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("Full happy path: generate foreign token → exchange → receive valid sandbox token")
    void fullHappyPath() throws Exception {
        // ── Step 1: Generate a mock foreign token ─────────────────────────────
        MvcResult step1 = mockMvc.perform(get("/mock-idp/generate-test-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.foreign_token").isString())
                .andReturn();

        String foreignToken = (String) objectMapper
                .readValue(step1.getResponse().getContentAsString(), Map.class)
                .get("foreign_token");
        assertThat(foreignToken).isNotBlank();

        // ── Step 2: Exchange for a UIDAI sandbox token ────────────────────────
        MvcResult step2 = mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"" + foreignToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sandbox_session_token").isString())
                .andReturn();

        String sandboxToken = (String) objectMapper
                .readValue(step2.getResponse().getContentAsString(), Map.class)
                .get("sandbox_session_token");
        assertThat(sandboxToken).isNotBlank();

        // ── Step 3: Decode and assert sandbox token claims ────────────────────
        JWTClaimsSet claims = SignedJWT.parse(sandboxToken).getJWTClaimsSet();

        assertThat(claims.getSubject()).isEqualTo("eu-usr-88372");
        assertThat(claims.getStringClaim("full_name")).isEqualTo("Elena Rostova");
        assertThat(claims.getIssuer()).isEqualTo("https://sandbox.uidai.gov.in");
        assertThat(claims.getStringClaim("assurance_level")).isEqualTo("HIGH");
        assertThat(claims.getExpirationTime()).isNotNull();
        assertThat(claims.getJWTID()).isNotBlank();
    }

    @Test
    @DisplayName("Two sequential exchanges produce different jti values (no token replay)")
    void twoExchanges_produceDifferentJtis() throws Exception {
        String sandboxToken1 = doFullExchange();
        String sandboxToken2 = doFullExchange();

        String jti1 = SignedJWT.parse(sandboxToken1).getJWTClaimsSet().getJWTID();
        String jti2 = SignedJWT.parse(sandboxToken2).getJWTClaimsSet().getJWTID();

        assertThat(jti1).isNotEqualTo(jti2);
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private String doFullExchange() throws Exception {
        MvcResult r1 = mockMvc.perform(get("/mock-idp/generate-test-token")).andReturn();
        String foreignToken = (String) objectMapper
                .readValue(r1.getResponse().getContentAsString(), Map.class)
                .get("foreign_token");

        MvcResult r2 = mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"" + foreignToken + "\"}"))
                .andReturn();
        return (String) objectMapper
                .readValue(r2.getResponse().getContentAsString(), Map.class)
                .get("sandbox_session_token");
    }
}
