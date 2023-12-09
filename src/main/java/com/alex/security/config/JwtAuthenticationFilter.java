package com.alex.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    /*
    Sending Authorization Bearer Token Header

    GET /echo/get/json HTTP/1.1
    Host: reqbin.com
    Accept: application/json
    Authorization: Bearer <token>
     */

    /* JWT Template
    Header
        {
          "alg": "HS256",
          "typ": "JWT"
        }.
    Payload
        {
          "sub": "1234567890",
          "name": "John Doe",
          "authorities": [
              "ADMIN",
              "MANAGER"
          ]
        }.
     Signature
         HMACSHA256(
          base64UrlEncode(header) + "." +
          base64UrlEncode(payload),
          secret)
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        final String jwtToken = authHeader.substring("Bearer ".length());
        final String userEmail = jwtService.extractUsername(jwtToken);

    }
}
