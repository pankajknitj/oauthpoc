package com.example.practice_ss.config.oauth;

import com.example.practice_ss.exception.CustomBassicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.practice_ss.constans.ApplicationConstants.OAUTH2;
import static com.example.practice_ss.constans.Paths.*;

@Profile(OAUTH2)
@Configuration
public class OAuth2SecurityConfig {

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

        http.oauth2ResourceServer(orc -> orc.jwt(jwtConfigurer ->
                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));

        http.csrf(csrf -> csrf.disable()) ; // Disable CSRF for H2 console
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        return http.build();
    }
}
