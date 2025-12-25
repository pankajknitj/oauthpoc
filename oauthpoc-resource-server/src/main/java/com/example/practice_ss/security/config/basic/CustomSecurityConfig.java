package com.example.practice_ss.security.config.basic;

import com.example.practice_ss.security.service.CustomJdbcUserDetailsService;
import com.example.practice_ss.security.service.HttpSecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;


@Profile(BASIC_AUTH)
@Configuration
@RequiredArgsConstructor
public class CustomSecurityConfig {
    private final HttpSecurityService httpSecurityService;

    @Bean
    AuthenticationManager authenticationManager(AuthenticationProvider provider){
        return new ProviderManager(provider);
    }


    /*In memory user details service*/
    @Bean("inMemoryUserDetailsService")
    UserDetailsService inMemoryUserDetailsService(){
        UserDetails user1 = User.withUsername("pankaj").password("{noop}password").authorities("admin").build();
        UserDetails user2 = User.withUsername("anjali").password("{bcrypt}$2a$12$8t3MCTsNaV3wgcEXP2cnc.M2PcuXsxZBgxybggY6W98h5gpufkXXW").authorities("read").build();
        return new InMemoryUserDetailsManager(user1,user2);
    }

    /*JDBC user details service to retrieve user from database*/
    @Bean("jdbcUserDetailsService")
    UserDetailsService jdbcUserDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }

    /*Custom user details service to store user with own attributes*/
    @Bean("customUserDetailsService")
    @Primary
    UserDetailsService customUserDetailsService(CustomJdbcUserDetailsService userDetailsService){
        return userDetailsService;
    }
}
