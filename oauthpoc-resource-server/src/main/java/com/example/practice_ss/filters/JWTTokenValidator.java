package com.example.practice_ss.filters;

import com.example.practice_ss.constans.ApplicationConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.coyote.BadRequestException;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.example.practice_ss.constans.ApplicationConstants.*;
import static com.example.practice_ss.constans.Paths.LOGIN;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class JWTTokenValidator extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = request.getHeader(AUTHORIZATION);
        if(jwt != null){
            Environment env = getEnvironment();
            String secrete = env.getProperty("auth.secrete",ApplicationConstants.AUTH_DEFAULT_SECRETE);

            SecretKey secretKey = Keys.hmacShaKeyFor(secrete.getBytes(StandardCharsets.UTF_8));
            if(secretKey != null){
                try{
                    Claims claims = Jwts.parser().verifyWith(secretKey)
                            .build().parseSignedClaims(jwt).getPayload();

                    String userName = (String) claims.get(USERNAME);
                    String authorities = (String) claims.get(AUTHORITIES);

                    Authentication authentication = new UsernamePasswordAuthenticationToken(userName,null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }catch (Exception e){
                    throw new BadCredentialsException("Invalid Token");
                }
            }
        }else{
            throw new BadCredentialsException("Token is expected.");
        }
        filterChain.doFilter(request,response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals(LOGIN.toString());
    }
}
