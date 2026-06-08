package com.securegate.filter;

import com.securegate.config.RSAKeyConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JWT authentication filter — runs third in the security chain.
 * Verifies RSA-2048 RS256 signature and expiration, then sets SecurityContext.
 * Only public claims (sub, scope) are forwarded — no PII.
 */
@Component
@Order(-80)
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final RSAKeyConfig rsaKeyConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String path = request.getRequestURI();

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            if (isPublicPath(path)) {
                chain.doFilter(request, response);
                return;
            }
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Missing Authorization header\"}");
            return;
        }

        try {
            String token = authHeader.substring(7);

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(rsaKeyConfig.getPublicKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String userId = claims.getSubject();
            String scope = claims.get("scope", String.class);

            if (userId == null || userId.isEmpty()) {
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Invalid token: missing subject\"}");
                return;
            }

            List<SimpleGrantedAuthority> authorities = (scope != null && !scope.isEmpty())
                    ? Arrays.stream(scope.split("\\s+"))
                            .map(SimpleGrantedAuthority::new)
                            .toList()
                    : List.of();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("JWT AUTH FILTER: Authenticated user={}, scope={}, jti={}",
                    userId, scope, claims.getId());

            chain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            log.debug("JWT AUTH FILTER: Token expired");
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Token has expired. Please login again.\"}");
        } catch (JwtException e) {
            log.warn("JWT AUTH FILTER: Signature verification FAILED, IP={}",
                    request.getRemoteAddr());
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Invalid token signature\"}");
        } catch (Exception e) {
            log.error("JWT AUTH FILTER: Unexpected error during verification", e);
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Token verification failed\"}");
        }
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/api/v1/auth/register")
                || path.startsWith("/api/v1/auth/login");
    }

    private void sendError(HttpServletResponse response, int status, String body)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(body);
    }
}
