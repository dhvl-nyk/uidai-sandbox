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

// MOCK environment: MockMvc intercepts requests in-process — no real HTTP port
// is bound, so this test can run alongside a live app or other test classes
// without any port conflict.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@DisplayName("GatewayController — /api/v1/interoperability/exchange")
class GatewayControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MockForeignIdpService mockForeignIdpService;

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /exchange with a valid foreign token returns 200 and a sandbox_session_token")
    void exchange_validToken_returns200() throws Exception {
        String foreignToken = mockForeignIdpService.generateMockForeignToken();

        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"" + foreignToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sandbox_session_token").isString())
                .andExpect(jsonPath("$.sandbox_session_token", not(emptyString())));
    }

    @Test
    @DisplayName("POST /exchange response token is a three-part JWT")
    void exchange_validToken_returnsJwtShape() throws Exception {
        String foreignToken = mockForeignIdpService.generateMockForeignToken();

        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"" + foreignToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sandbox_session_token",
                        matchesPattern("^[\\w-]+\\.[\\w-]+\\.[\\w-]+$")));
    }

    // ── Bad request cases ─────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /exchange with missing foreign_token field returns 400")
    void exchange_missingField_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("foreign_token is required"));
    }

    @Test
    @DisplayName("POST /exchange with empty foreign_token value returns 400")
    void exchange_emptyToken_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("foreign_token is required"));
    }

    @Test
    @DisplayName("POST /exchange with empty body returns 400")
    void exchange_emptyBody_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // ── Security / auth failure cases ─────────────────────────────────────────

    @Test
    @DisplayName("POST /exchange with a tampered token returns 401 with generic error")
    void exchange_tamperedToken_returns401() throws Exception {
        String foreignToken = mockForeignIdpService.generateMockForeignToken();
        String[] parts = foreignToken.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "." +
                (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);

        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"" + tampered + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error")
                        .value("Authentication failed. Trust could not be verified."));
    }

    @Test
    @DisplayName("POST /exchange with a garbage token returns 401")
    void exchange_garbageToken_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/interoperability/exchange")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"foreign_token\":\"this.is.garbage\"}"))
                .andExpect(status().isUnauthorized());
    }

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

    @Test
    @DisplayName("GET /mock-idp/.well-known/jwks.json key type is RSA")
    void mockIdp_jwks_keyTypeIsRsa() throws Exception {
        mockMvc.perform(get("/mock-idp/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
    }

    @Test
    @DisplayName("GET /mock-idp/.well-known/jwks.json does not expose private key 'd' parameter")
    void mockIdp_jwks_doesNotExposePrivateKey() throws Exception {
        mockMvc.perform(get("/mock-idp/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }
}
