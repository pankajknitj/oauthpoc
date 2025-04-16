package com.example.practice_ss.controller;

import com.example.practice_ss.dto.UserDto;
import com.example.practice_ss.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@RestController
public class UserController {
    @Autowired
    UserService userService;
    @PostMapping("/user/create")
    public ResponseEntity<?> createUser(@RequestBody UserDto userDto){
        userService.createUser(userDto);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }
}
