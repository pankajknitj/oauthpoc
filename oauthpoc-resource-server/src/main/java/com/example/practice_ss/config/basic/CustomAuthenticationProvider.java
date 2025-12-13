package com.example.practice_ss.config.basic;

import com.example.practice_ss.config.basic.factory.UserDetailsServiceFactory;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@Component
public class CustomAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    UserDetailsServiceFactory userDetailsServiceFactory;

    @Autowired
    PasswordEncoder passwordEncoder;

    private UserDetailsService userDetailsService;

    @PostConstruct
    void init(){
        this.userDetailsService = userDetailsServiceFactory.getUseDetailsService();
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        String rawPwd = authentication.getCredentials().toString();
        String storedPwd = userDetails.getPassword();
        if(!passwordEncoder.matches(rawPwd, storedPwd)){
            throw new BadCredentialsException("Password is Incorrect");
        }
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User is not registered");
        }
        return user;
    }
}
