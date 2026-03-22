package com.uidai.sandbox.controller;

import com.uidai.sandbox.service.TokenTranslationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/interoperability")
public class GatewayController {

    private final TokenTranslationService translationService;

    public GatewayController(TokenTranslationService translationService) {
        this.translationService = translationService;
    }

    @PostMapping("/exchange")
    public ResponseEntity<?> exchangeToken(@RequestBody Map<String, String> request) {
        String foreignToken = request.get("foreign_token");
        if (foreignToken == null || foreignToken.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "foreign_token is required"));
        }

        String sandboxToken = translationService.exchangeToken(foreignToken);
        return ResponseEntity.ok(Map.of("sandbox_session_token", sandboxToken));
    }

    // Global Exception Handling for Security Events
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<?> handleSecurityFailure(SecurityException ex) {
        // Log the exact error securely (e.g., to Kafka) without exposing stack traces to the client
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Authentication failed. Trust could not be verified."));
    }
}