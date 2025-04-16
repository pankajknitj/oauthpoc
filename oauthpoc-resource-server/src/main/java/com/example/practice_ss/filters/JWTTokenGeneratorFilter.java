package com.example.practice_ss.filters;

import com.example.practice_ss.constans.ApplicationConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

import static com.example.practice_ss.constans.Paths.LOGIN;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null){
            Environment env = getEnvironment();
            String secrete = env.getProperty("auth.secrete", ApplicationConstants.AUTH_DEFAULT_SECRETE);
            SecretKey secretKey = Keys.hmacShaKeyFor(secrete.getBytes(StandardCharsets.UTF_8));

            String userName = authentication.getName();
            String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

            String jwt = Jwts.builder()
                    .issuer("Dinchak Bank")
                    .subject("Dinchak")
                    .claim(ApplicationConstants.USERNAME,userName)
                    .claim(ApplicationConstants.AUTHORITIES, authorities)
                    .issuedAt(new Date())
                    .expiration(new Date(new Date().getTime() + 300000))
                    .signWith(secretKey)
                    .compact();

            response.setHeader(ApplicationConstants.AUTHORIZATION,jwt);
        }

        filterChain.doFilter(request,response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals(LOGIN.toString());
    }
}
