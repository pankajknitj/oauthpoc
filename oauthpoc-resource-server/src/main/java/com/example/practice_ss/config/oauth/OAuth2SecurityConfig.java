package com.example.practice_ss.config.oauth;

import com.example.practice_ss.exception.CustomBassicAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.practice_ss.constans.ApplicationConstants.OAUTH2;
import static com.example.practice_ss.constans.Paths.*;

@Profile(OAUTH2)
@Configuration
public class OAuth2SecurityConfig {
    @Autowired
    Environment environment;

    @Bean
    SecurityFilterChain CustomSecurityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers(CONTACTS.toString(), NOTICES.toString(), H2_CONSOLE.toString(), GET_TOKEN.toString()).permitAll()
                .requestMatchers(MY_ACCOUNT.toString()).hasRole("ACCOUNT_READ")
                .requestMatchers(MY_CARDS.toString()).hasRole("CARDS_READ")
                .requestMatchers(MY_BALANCE.toString(),MY_LOANS.toString(),USER.toString()).authenticated()
        );
        http.oauth2Login(oc -> oc.defaultSuccessUrl("/myCards",true)
                .userInfoEndpoint(userInfo ->
                        userInfo.oidcUserService(new KeycloakOIDCUserService())
                ));

        http.oauth2ResourceServer(orc -> orc.jwt(jwtConfigurer ->
                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));

        http.csrf(csrf -> csrf.disable()) ; // Disable CSRF for H2 console
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        return http.build();
    }

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
