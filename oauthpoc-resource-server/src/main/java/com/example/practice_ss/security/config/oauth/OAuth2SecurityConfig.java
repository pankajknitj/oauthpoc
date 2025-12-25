package com.example.practice_ss.security.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static com.example.practice_ss.constans.ApplicationConstants.OAUTH2;

//@RequiredArgsConstructor
@Profile(OAUTH2)
@Configuration
public class OAuth2SecurityConfig {

    @Autowired
    private Environment environment;

    @Bean
    public ClientRegistrationRepository clientRegistration() {
        return new InMemoryClientRegistrationRepository(keyckloakClientRegistration());
    }

    @Bean
    public ClientRegistration keyckloakClientRegistration() {
        String clientId = environment.getProperty("application.security.keycloak.client-id");
        String clientSecret = environment.getProperty("application.security.keycloak.client-secret");
        String tokenUri = environment.getProperty("application.security.keycloak.token-uri");
        String authUri = environment.getProperty("application.security.keycloak.auth-uri");
        String issuerUri = environment.getProperty("application.security.keycloak.issuer-uri");
        String userInfoUri = environment.getProperty("application.security.keycloak.userInfo-uri");
        String jwkSetUri = environment.getProperty("application.security.keycloak.jwks-uri");
        String redirectUri = "{baseUrl}/login/oauth2/code/{registrationId}";

        return ClientRegistration.withRegistrationId("KEYCLOAK")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope(new String[]{"openid", "email"})
                .issuerUri(issuerUri)
                .userInfoUri(userInfoUri)
                .jwkSetUri(jwkSetUri)
                .userNameAttributeName("preferred_username")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .tokenUri(tokenUri)
                .authorizationUri(authUri)
                .build();
    }
}
