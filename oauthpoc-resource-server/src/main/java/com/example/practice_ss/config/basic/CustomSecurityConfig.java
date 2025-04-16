package com.example.practice_ss.config.basic;

import com.example.practice_ss.exception.CustomAccessDeniedHandler;
import com.example.practice_ss.exception.CustomBassicAuthenticationEntryPoint;
import com.example.practice_ss.filters.LoggingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;
import static com.example.practice_ss.constans.Paths.*;

@Profile(BASIC_AUTH)
@Configuration
public class CustomSecurityConfig {

    @Bean
    SecurityFilterChain CustomSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers(CONTACTS.toString(), NOTICES.toString(), H2_CONSOLE.toString(), GET_TOKEN.toString()).permitAll()
                .requestMatchers(MY_ACCOUNT.toString()).hasAuthority("ACCOUNT_READ")
                .requestMatchers(MY_CARDS.toString()).hasAuthority("CARDS_READ")
                .requestMatchers(MY_BALANCE.toString(),MY_LOANS.toString(),USER.toString()).authenticated()
        );

//        http.addFilterBefore(new RequestValidationFilter(), BasicAuthenticationFilter.class);
        http.addFilterAfter(new LoggingFilter(),BasicAuthenticationFilter.class);
//        http.addFilterAfter(new JWTTokenGeneratorFilter(),BasicAuthenticationFilter.class);
//        http.addFilterBefore(new JWTTokenValidator(),BasicAuthenticationFilter.class);

        http.formLogin(flc->flc.disable());
        http.httpBasic(hbc->hbc.authenticationEntryPoint(new CustomBassicAuthenticationEntryPoint()));

        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));

        http.sessionManagement(sc->sc.maximumSessions(1).maxSessionsPreventsLogin(true).expiredUrl("/behenkalaodatuhaikon"));

        http.csrf(csrf -> csrf.disable()) ; // Disable CSRF for H2 console
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        return http.build();
    }
    @Bean
    PasswordEncoder defaultPasswordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /*In memory user details service*/
//    @Bean
//    UserDetailsService customUserDetailsService(){
//        UserDetails user1 = User.withUsername("pankaj").password("{noop}password").authorities("admin").build();
//        UserDetails user2 = User.withUsername("anjali").password("{bcrypt}$2a$12$8t3MCTsNaV3wgcEXP2cnc.M2PcuXsxZBgxybggY6W98h5gpufkXXW").authorities("read").build();
//        return new InMemoryUserDetailsManager(user1,user2);
//    }

    /*JDBC user details service to retrieve user from database*/
//    @Bean
//    UserDetailsService customUserDetailsService(DataSource dataSource){
//        return new JdbcUserDetailsManager(dataSource);
//    }


    @Bean
    AuthenticationManager authenticationManager(AuthenticationProvider provider){
        return new ProviderManager(provider);
    }
}
