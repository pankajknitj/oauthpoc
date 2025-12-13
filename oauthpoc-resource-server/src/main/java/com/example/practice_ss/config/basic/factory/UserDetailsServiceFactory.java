package com.example.practice_ss.config.basic.factory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@Service
public class UserDetailsServiceFactory {
    @Value("${basic.auth.user-details-service}")
    private String userDetailsServiceName;
    @Autowired
    private ApplicationContext applicationContext;

    public UserDetailsService getUseDetailsService(){
        return (UserDetailsService) applicationContext.getBean(userDetailsServiceName);
    }
}
