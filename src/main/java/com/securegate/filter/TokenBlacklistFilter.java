package com.securegate.filter;

import com.securegate.service.TokenBlacklistService;
import com.securegate.util.JwtDecodeUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Token blacklist filter — runs second in the security chain.
 * Checks Redis for revoked JWT IDs before signature verification.
 */
@Component
@Order(-90)
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistFilter extends OncePerRequestFilter {

    private static final String ERROR_BODY =
            "{\"error\":\"Security Alert: This token has been revoked.\"}";

    private final TokenBlacklistService blacklistService;

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
            String jti = JwtDecodeUtil.extractJti(token);

            if (jti == null || jti.isEmpty()) {
                log.warn("BLACKLIST FILTER: Token missing jti claim, IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                        "{\"error\":\"Invalid token: missing JWT ID (jti)\"}");
                return;
            }

            if (blacklistService.isBlacklisted(jti)) {
                log.warn("BLACKLIST FILTER: Revoked token detected — jti={}, IP={}",
                        jti, request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            chain.doFilter(request, response);

        } catch (IllegalArgumentException e) {
            log.warn("BLACKLIST FILTER: Malformed JWT, IP={}",
                    request.getRemoteAddr());
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "{\"error\":\"Invalid JWT format\"}");
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
