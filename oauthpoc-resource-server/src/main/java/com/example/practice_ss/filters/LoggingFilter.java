package com.example.practice_ss.filters;

import jakarta.servlet.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;

@Slf4j
public class LoggingFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if( authentication != null){
            String userName = authentication.getName();
            String roles = authentication.getAuthorities().toString();

            log.info(userName + " logged in with following roles: "+ roles);
        }
        chain.doFilter(request,response);
    }
}
