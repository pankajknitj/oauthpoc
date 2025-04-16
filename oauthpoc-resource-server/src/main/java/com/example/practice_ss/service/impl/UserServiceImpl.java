package com.example.practice_ss.service.impl;

import com.example.practice_ss.dto.UserDto;
import com.example.practice_ss.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserDetailsService userDetailsService;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public void createUser(UserDto userDto) {
        UserDetails user = User.withUsername(userDto.getUserName())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .authorities(userDto.getAuthority())
                .build();
        ((UserDetailsManager)userDetailsService).createUser(user);
    }
}
