package com.example.practice_ss.service;

import com.example.practice_ss.dto.UserDto;
import org.springframework.security.core.userdetails.User;

public interface UserService {
    public void createUser(UserDto userDto);
}
