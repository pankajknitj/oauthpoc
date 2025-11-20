package com.example.practice_ss.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyBalanceController {
//    @PreAuthorize("hasAuthority('BALANCE_READ')")
    @GetMapping("/myBalance")
    public ResponseEntity<String> getBalance(Authentication authentication){
        System.out.println(authentication);
        return new ResponseEntity<>("Balance is working", HttpStatus.ACCEPTED);
    }
}
