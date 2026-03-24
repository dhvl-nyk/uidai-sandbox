package com.uidai.sandbox.controller;

import com.uidai.sandbox.mock.MockForeignIdpService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/mock-idp")
public class MockIdpController {

    private final MockForeignIdpService mockIdpService;

    public MockIdpController(MockForeignIdpService mockIdpService) {
        this.mockIdpService = mockIdpService;
    }

    // This is the endpoint TokenTranslationService dynamically reaches out to
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        return mockIdpService.getJwks();
    }

    // A helper endpoint to generate a valid token to test
    @GetMapping("/generate-test-token")
    public ResponseEntity<Map<String, String>> generateToken() {
        try {
            String token = mockIdpService.generateMockForeignToken();
            return ResponseEntity.ok(Map.of("foreign_token", token));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}