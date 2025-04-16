package com.rgbpvt.rgpvt_client.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    @Autowired
    private OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    public String getAccessToken(){
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak_internal")
                .principal("system-app")
                .build();

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            throw new IllegalStateException("User is not authorized or access token is missing");
        }

        return authorizedClient.getAccessToken().getTokenValue();
    }

}
