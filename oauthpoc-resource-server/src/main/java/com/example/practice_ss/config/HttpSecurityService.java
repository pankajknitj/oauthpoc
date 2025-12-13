package com.example.practice_ss.config;

import com.example.practice_ss.config.oauth.KeycloakOIDCUserService;
import com.example.practice_ss.config.oauth.KeycloakRoleConverter;
import com.example.practice_ss.exception.AccessDeniedHandler;
import com.example.practice_ss.exception.AuthenticationEntryPoint;
import com.example.practice_ss.filters.LoggingFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Service;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collection;
import java.util.Collections;

import static com.example.practice_ss.constans.Paths.*;

@Service
public class HttpSecurityService {

    public HttpSecurity applyCommonConfig(HttpSecurity http) throws Exception {
        /*common configuration used in all type of authentication
        * Basic authentication, Oauth2
        * Resource server*/
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers(CONTACTS.toString(), NOTICES.toString(), H2_CONSOLE.toString(), GET_TOKEN.toString()).permitAll()
                .requestMatchers(MY_ACCOUNT.toString()).hasRole("ACCOUNT_READ")
                .requestMatchers(MY_CARDS.toString()).hasRole("CARDS_READ")
                .requestMatchers(MY_BALANCE.toString(),MY_LOANS.toString(),USER.toString()).authenticated()
        );

        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new AccessDeniedHandler()));

        http.cors(corsConfig -> corsConfig.configurationSource(getCorsConfiguration()));
        http.csrf(csrf -> csrf.disable()) ; // Disable CSRF for H2 console
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

        return http;
    }

    /*CORS configuration, required when UI and Backend running on different servers*/
    private CorsConfigurationSource getCorsConfiguration(){
        return new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration corsConfiguration = new CorsConfiguration();
                corsConfiguration.setAllowedOriginPatterns(Collections.singletonList("http://localhost:4200"));
                corsConfiguration.setAllowCredentials(true);
                corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                return corsConfiguration;
            }
        };
    }


    /*Responsible for oauth login flow*/
    public void configureOauth2Login(HttpSecurity http) throws Exception {
        http.oauth2Login(oc -> oc.defaultSuccessUrl("/myCards",true)
                .userInfoEndpoint(userInfo ->
                        userInfo.oidcUserService(new KeycloakOIDCUserService())
                )
        );
    }

    /*Responsible to make application as resource server, it requires a JWT role converter, so that it can validate the roles*/
    public void configureResourceServer(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

        http.oauth2ResourceServer(orc -> orc.jwt(jwtConfigurer ->
                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
    }

    public void configureFormLogin(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(request ->
                request.requestMatchers("/login").permitAll());
        http.formLogin(Customizer.withDefaults());
    }

    public void configureBasicAuthentication(HttpSecurity http) throws Exception {
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new AuthenticationEntryPoint())
        );
    }

    public void configureRequiredFilters(HttpSecurity http){
        //        http.addFilterBefore(new RequestValidationFilter(), BasicAuthenticationFilter.class);
        http.addFilterAfter(new LoggingFilter(), BasicAuthenticationFilter.class);
//        http.addFilterAfter(new JWTTokenGeneratorFilter(),BasicAuthenticationFilter.class);
//        http.addFilterBefore(new JWTTokenValidator(),BasicAuthenticationFilter.class);
    }

}
