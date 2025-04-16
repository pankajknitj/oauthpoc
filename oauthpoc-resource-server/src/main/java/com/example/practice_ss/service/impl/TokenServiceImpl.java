package com.example.practice_ss.service.impl;

import com.example.practice_ss.constans.ApplicationConstants;
import com.example.practice_ss.model.Customer;
import com.example.practice_ss.service.TokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final AuthenticationManager authenticationManager;

    @Override
    public String generateToken(Customer customer) {
        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(customer.getEmail(),customer.getPwd());

        Authentication authenticationRes = authenticationManager.authenticate(authentication);
        return getToken(authenticationRes);
    }


    private String getToken(Authentication authentication){
        String secrete = ApplicationConstants.AUTH_DEFAULT_SECRETE;
        SecretKey secretKey = Keys.hmacShaKeyFor(secrete.getBytes(StandardCharsets.UTF_8));

        String userName = authentication.getName();
        String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        return Jwts.builder()
                .issuer("Dinchak Bank")
                .subject("Dinchak")
                .claim(ApplicationConstants.USERNAME,userName)
                .claim(ApplicationConstants.AUTHORITIES, authorities)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + 300000))
                .signWith(secretKey)
                .compact();
    }
}
