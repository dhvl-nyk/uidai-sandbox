# UIDAI Sandbox: Cross-Border Trust Broker (Token Translation Service)

This repository contains the core backend logic for the **Token Translation & Verification Service**, developed as Part 2 of the UIDAI Sandbox Technical Architect evaluation.

Built with **Java** and **Spring Boot**, this service acts as a secure interoperability gateway, allowing foreign citizens to authenticate into the Sandbox environment. It dynamically verifies cryptographically signed foreign identity tokens, normalizes the claims, and issues standardized Sandbox Session Tokens.

---

## 🏗️ Architectural Decisions & Key Features

* **Dynamic Trust Anchor Resolution:** Utilizes the `nimbus-jose-jwt` library to dynamically fetch and cache public keys from a foreign Identity Provider's JWKS endpoint based on the token's `kid` header.
* **Zero Hardcoded Keys:** Cryptographic verification is handled entirely dynamically, ensuring seamless key rotation without system downtime.
* **Robust Error Management:** Handles unreachable external JWKS endpoints and invalid signatures gracefully, returning standardized `401 Unauthorized` responses without leaking internal stack traces.
* **Embedded Mock IdP:** Includes a self-contained Mock Foreign Identity Provider to facilitate easy local testing without relying on external network dependencies.

---

## ⚙️ Prerequisites

* Java 17 or higher
* Maven 3.8+

---
## ⚙️ How to run

```bash
mvn clean install
mvn spring-boot:run

1. Get a Mock Foreign Token
curl -X GET http://localhost:8080/mock-idp/generate-test-token

2. Execute the Token Exchange
curl -X POST http://localhost:8080/api/v1/interoperability/exchange \
     -H "Content-Type: application/json" \
     -d '{"foreign_token": "<PASTE_TOKEN_HERE>"}'
```