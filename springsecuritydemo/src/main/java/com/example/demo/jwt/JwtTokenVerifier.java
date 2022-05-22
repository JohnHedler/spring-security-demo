package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

// Class JwtTokenVerifier extends OncePerRequestFilter because it should only do the filtering once per request:
public class JwtTokenVerifier extends OncePerRequestFilter {

    // Data members
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    // Constructor
    public JwtTokenVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Retrieve the JSON Web Token from the request header:
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        // Check if the Authorization value is null or empty.
        // Also check to see if the value does not start with "Bearer ".
        // If this check returns that there is no token or the token starts with the wrong String literal,
        //  then, return to reject the request:
        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        // Remove "Bearer " from the beginning of the value to get the token:
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try {
            // Parse out the JSON Web Token:
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            // Get the body of the Claim:
            Claims body = claimsJws.getBody();

            // Get the username from the body:
            String username = body.getSubject();

            // Get the list of authorities from the body:
            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");

            // Retrieve the set of the authorities from the body:
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            // Get the authentication:
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            // Set the authentication to be true (says that the client has been authenticated):
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        // The initial request/response will be passed onto the next filter.
        // This allows the information to be passed into the API so that it can return values:
        filterChain.doFilter(request, response);
    }
}
