package com.securegate.service;

import com.securegate.config.RSAKeyConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

/**
 * JWT creation and parsing service using RSA RS256 asymmetric keys.
 *
 * STRICT PAYLOAD RULE: only public claims are included:
 *   sub, scope, jti, iat, exp — no PII, emails, or passwords.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    private final RSAKeyConfig rsaKeyConfig;

    @Value("${jwt.access-token-expiry:900}")
    private long accessTokenExpirySeconds;

    public String createAccessToken(String userId, String role) {
        try {
            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            Date exp = new Date(nowMillis + accessTokenExpirySeconds * 1000);
            String jti = UUID.randomUUID().toString();

            String token = Jwts.builder()
                    .setSubject(userId)
                    .claim("scope", role)
                    .setId(jti)
                    .setIssuedAt(now)
                    .setExpiration(exp)
                    .signWith(rsaKeyConfig.getPrivateKey())
                    .compact();

            log.debug("JWT created: sub={}, jti={}, exp={}, scope={}",
                    userId, jti, exp, role);
            return token;

        } catch (Exception e) {
            log.error("JWT creation failed for user={}", userId, e);
            throw new RuntimeException("JWT creation failed", e);
        }
    }

    public Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(rsaKeyConfig.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            log.warn("Failed to parse JWT claims", e);
            throw new RuntimeException("Invalid token format", e);
        }
    }

    public long getRemainingTtlSeconds(Date expiration) {
        if (expiration == null) {
            return 0;
        }
        long remaining = (expiration.getTime() - System.currentTimeMillis()) / 1000;
        return Math.max(remaining, 0);
    }
}
