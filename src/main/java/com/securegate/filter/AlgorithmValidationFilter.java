package com.securegate.filter;

import com.securegate.util.JwtDecodeUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Proactive algorithm validation — runs first in the security chain.
 * Decodes the JWT header and inspects "alg" before cryptographic verification.
 */
@Component
@Order(-100)
@Slf4j
public class AlgorithmValidationFilter extends OncePerRequestFilter {

    private static final Set<String> SYMMETRIC_ALGORITHMS = Set.of(
            "HS256", "HS384", "HS512",
            "hs256", "hs384", "hs512");
    private static final Set<String> NONE_ALGORITHMS = Set.of(
            "none", "None", "NONE");
    private static final String EXPECTED_ALGORITHM = "RS256";

    private static final String ERROR_BODY =
            "{\"error\":\"Security Violation: Invalid or manipulated algorithm detected\"}";

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
            String algName = JwtDecodeUtil.extractAlgorithm(token);

            if (algName == null || algName.isBlank()) {
                log.warn("PROACTIVE BLOCK: Missing 'alg' in JWT header from IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            if (NONE_ALGORITHMS.contains(algName)) {
                log.warn("PROACTIVE BLOCK: Algorithm Confusion — 'none' attack from IP={}",
                        request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            if (SYMMETRIC_ALGORITHMS.contains(algName)) {
                log.warn("PROACTIVE BLOCK: Algorithm Confusion — symmetric {} when RS256 expected, IP={}",
                        algName, request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            if (!EXPECTED_ALGORITHM.equals(algName)) {
                log.warn("PROACTIVE BLOCK: Unexpected algorithm '{}' when RS256 expected, IP={}",
                        algName, request.getRemoteAddr());
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
                return;
            }

            chain.doFilter(request, response);

        } catch (IllegalArgumentException e) {
            log.warn("PROACTIVE BLOCK: Malformed JWT — cannot parse header, IP={}",
                    request.getRemoteAddr());
            sendError(response, HttpServletResponse.SC_UNAUTHORIZED, ERROR_BODY);
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
