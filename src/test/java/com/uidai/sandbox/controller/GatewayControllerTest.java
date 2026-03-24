package com.uidai.sandbox.controller;

import com.uidai.sandbox.mock.MockForeignIdpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@DisplayName("GatewayController — /api/v1/interoperability/exchange")
class GatewayControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MockForeignIdpService mockForeignIdpService;

    @Test
    @DisplayName("POST /exchange with missing foreign_token field returns 400")
    void exchange_missingField_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("foreign_token is required"));
    }

    // ── Security / auth failure cases ─────────────────────────────────────────

    @Test
    @DisplayName("POST /exchange error body does NOT leak internal exception details")
    void exchange_tamperedToken_doesNotLeakDetails() throws Exception {
        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"bad.token.here\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error")
                        .value("Authentication failed. Trust could not be verified."));
    }

    // ── Mock IdP endpoints ────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /mock-idp/generate-test-token returns 200 and a foreign_token")
    void mockIdp_generateToken_returns200() throws Exception {
        mockMvc.perform(get("/mock-idp/generate-test-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.foreign_token").isString())
                .andExpect(jsonPath("$.foreign_token", not(emptyString())));
    }

    @Test
    @DisplayName("GET /mock-idp/.well-known/jwks.json returns a JWKS with keys array")
    void mockIdp_jwks_returnsKeys() throws Exception {
        mockMvc.perform(get("/mock-idp/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys", hasSize(1)));
    }
}
