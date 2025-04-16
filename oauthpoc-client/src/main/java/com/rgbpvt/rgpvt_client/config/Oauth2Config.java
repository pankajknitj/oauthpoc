package com.rgbpvt.rgpvt_client.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Oauth2Config {
    private final String KEYCLOAK = "keycloak";

//    @Autowired
//    private List<ClientRegistration> clientRegistrationRepositories;

    @Autowired
    private Environment environment;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request -> request.anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistration() {
        return new InMemoryClientRegistrationRepository(keyckloakClientRegistration(),googleClientRegistration(),keycloakClientRegistrationInternal());
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

        return ClientRegistration.withRegistrationId(KEYCLOAK)
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

    private ClientRegistration keycloakClientRegistrationInternal() {
        String clientId = environment.getProperty("application.security.keycloak.client-id");
        String clientSecret = environment.getProperty("application.security.keycloak.client-secret");
        String tokenUri = environment.getProperty("application.security.keycloak.token-uri");
        String authUri = environment.getProperty("application.security.keycloak.auth-uri");
        String issuerUri = environment.getProperty("application.security.keycloak.issuer-uri");
        String userInfoUri = environment.getProperty("application.security.keycloak.userInfo-uri");
        String jwkSetUri = environment.getProperty("application.security.keycloak.jwks-uri");
        String redirectUri = "{baseUrl}/login/oauth2/code/{registrationId}";

        return ClientRegistration.withRegistrationId("keycloak_internal")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
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

    private ClientRegistration googleClientRegistration(){
        return CommonOAuth2Provider.GOOGLE
                .getBuilder("google")
                .clientId("")
                .clientSecret("")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .refreshToken()  // optional, if you want refresh tokens
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository,
                        authorizedClientRepository);

        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        return authorizedClientManager;
    }

}
