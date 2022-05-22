package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // Declare the authentication manager for authenticating credentials:
    private final AuthenticationManager authenticationManager;

    // Declare the JwtConfig for configuration:
    private final JwtConfig jwtConfig;

    // Declare the SecretKey to get the secret key:
    private final SecretKey secretKey;

    // Constructor
    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig,
                                                      SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    // Attempt Authentication method - attempt to authenticate the username/password supplied in request:
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        // Try authenticating credentials from request; otherwise, throw a Runtime IOException:
        try {
            // Retrieve the credentials from the request sent to the server:
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            // Get the username and password from the request:
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            // Authenticate if the username exists and if the password matches, and assign to Authentication variable:
            Authentication authenticate = authenticationManager.authenticate(authentication);

            // Return whether authenticated or not:
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Successful Authentication method - When the authentication is successful, it is executed.
    // The result of this is to return the generated token in the response header that is sent to the client.
    @Override
    public void successfulAuthentication(HttpServletRequest request,
                                         HttpServletResponse response,
                                         FilterChain chain,
                                         Authentication authResult) throws IOException, ServletException {

        // Generate token to send to client:
        String token = Jwts.builder()
                // Get the username:
                .setSubject(authResult.getName())
                // Get the authorities:
                .claim("authorities", authResult.getAuthorities())
                // Set the date to be today:
                .setIssuedAt(new Date())
                // Set the expiration date to a determined length of time (this is set for two weeks from now):
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())))
                // Sign the token with the key:
                .signWith(secretKey)
                // Finalizes and converts all values into a JSON Web Token:
                .compact();

        // Return the token in the header of the response for future requests:
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
    }
}
