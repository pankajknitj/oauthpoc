package com.rgbpvt.rgpvt_client.controller;

import com.rgbpvt.rgpvt_client.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class TokenController {

    private final OAuth2AuthorizedClientService auth2AuthorizedClientService;
    private final TokenService tokenService;

    @GetMapping("/token")
    public ResponseEntity<?> getToken(){
        OAuth2AuthenticationToken authenticationToken = getAuthentication();
        String token = "";
        if(authenticationToken != null){
            OAuth2AuthorizedClient authorizedClient = auth2AuthorizedClientService
                    .loadAuthorizedClient(authenticationToken.getAuthorizedClientRegistrationId(), authenticationToken.getName());
            token = authorizedClient.getAccessToken().getTokenValue();
        }

        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping("/google-token")
    public ResponseEntity<?> getGoogleToken(OAuth2AuthenticationToken authentication){


        return ResponseEntity.status(HttpStatus.OK).body(tokenService.getAccessToken());
    }


    private OAuth2AuthenticationToken getAuthentication(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof OAuth2AuthenticationToken){
            return (OAuth2AuthenticationToken) authentication;
        }
        return null;
    }
}
