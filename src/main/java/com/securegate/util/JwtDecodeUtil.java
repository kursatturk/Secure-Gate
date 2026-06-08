package com.securegate.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;

/**
 * Stateless JWT segment decoding for proactive filters that must inspect
 * header or payload claims before cryptographic verification.
 */
public final class JwtDecodeUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwtDecodeUtil() {
    }

    public static String extractAlgorithm(String token) {
        JsonNode header = decodeSegment(token, 0);
        JsonNode alg = header.get("alg");
        return alg != null && !alg.isNull() ? alg.asText() : null;
    }

    public static String extractJti(String token) {
        JsonNode payload = decodeSegment(token, 1);
        JsonNode jti = payload.get("jti");
        return jti != null && !jti.isNull() ? jti.asText() : null;
    }

    private static JsonNode decodeSegment(String token, int segmentIndex) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token is empty");
        }
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Malformed JWT");
        }
        if (segmentIndex >= parts.length) {
            throw new IllegalArgumentException("JWT segment index out of range");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(parts[segmentIndex]);
            return MAPPER.readTree(decoded);
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed JWT segment", e);
        }
    }
}
