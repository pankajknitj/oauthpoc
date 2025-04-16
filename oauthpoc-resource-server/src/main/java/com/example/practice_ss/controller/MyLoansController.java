package com.example.practice_ss.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyLoansController {
    @GetMapping("/myLoans")
    public ResponseEntity<String> getLoans(){
        return new ResponseEntity<>("Loan is working", HttpStatus.ACCEPTED);
    }
}
