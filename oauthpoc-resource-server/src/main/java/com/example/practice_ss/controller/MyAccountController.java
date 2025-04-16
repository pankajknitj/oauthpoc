package com.example.practice_ss.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyAccountController {
    @GetMapping("/myAccount")
    public ResponseEntity<String> getAccount(){
        return new ResponseEntity<>("Account is working", HttpStatus.ACCEPTED);
    }
}
