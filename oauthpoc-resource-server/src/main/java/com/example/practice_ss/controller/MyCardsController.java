package com.example.practice_ss.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyCardsController {
    @GetMapping("/myCards")
    public ResponseEntity<String> getCards(){
        return new ResponseEntity<>("Cards is working", HttpStatus.ACCEPTED);
    }
}
