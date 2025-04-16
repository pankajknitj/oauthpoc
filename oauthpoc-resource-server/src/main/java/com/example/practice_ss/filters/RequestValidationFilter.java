package com.example.practice_ss.filters;

import ch.qos.logback.core.util.StringUtil;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

public class RequestValidationFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String header = req.getHeader(HttpHeaders.AUTHORIZATION);
        if(header != null){
            header = header.trim();
            if(StringUtils.startsWithIgnoreCase(header, "Basic ")){
                String base62Token = header.substring(6);
                try{
                    String decodeToken = new String(Base64.getDecoder().decode(base62Token));
                    int splitInd = decodeToken.indexOf(":");
                    if(splitInd == -1){
                        throw new BadCredentialsException("Invalid token");
                    }

                    String userName = decodeToken.substring(0,splitInd+1);
                    if(userName.toLowerCase().contains("test")){
                        res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        return;
                    }

                }catch (IllegalArgumentException e){
                    throw new BadCredentialsException(e.getMessage());
                }
            }else{
                throw new BadCredentialsException("Token is not valid");
            }
        }
        chain.doFilter(request,response);
    }
}
