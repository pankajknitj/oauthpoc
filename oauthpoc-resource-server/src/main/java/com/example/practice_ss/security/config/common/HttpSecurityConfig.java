package com.example.practice_ss.security.config.common;


import com.example.practice_ss.constans.ApplicationConstants;
import com.example.practice_ss.security.service.HttpSecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.List;

@Configuration
public class HttpSecurityConfig {

    @Autowired
    private HttpSecurityService httpSecurityService;

    @Autowired
    private Environment environment;

    @Bean
    SecurityFilterChain CustomSecurityFilterChain(HttpSecurity http) throws Exception {
        httpSecurityService.applyCommonConfig(http);

        List<String> activeProfiles = Arrays.asList(environment.getActiveProfiles());

        if(activeProfiles.contains(ApplicationConstants.BASIC_AUTH)){
            httpSecurityService.configureRequiredFilters(http);
            httpSecurityService.configureFormLogin(http);
            httpSecurityService.configureBasicAuthentication(http);
        }

        if(activeProfiles.contains(ApplicationConstants.OAUTH2)){
            httpSecurityService.configureOauth2Login(http);
            httpSecurityService.configureResourceServer(http);
        }

        http.sessionManagement(sc->sc.maximumSessions(1).maxSessionsPreventsLogin(true).expiredUrl("/behenkalaodatuhaikon"));

        return http.build();
    }
}
