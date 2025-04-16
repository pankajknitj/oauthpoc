package com.example.practice_ss.controller;

import com.example.practice_ss.dto.TokenReqDto;
import com.example.practice_ss.dto.UserDto;
import com.example.practice_ss.model.Customer;
import com.example.practice_ss.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@RestController
@RequiredArgsConstructor
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/token")
    public ResponseEntity<?> getToken(@RequestBody TokenReqDto req){
        Customer cust = new Customer();
        cust.setEmail(req.getUserName());
        cust.setPwd(req.getPassword());
        return ResponseEntity.status(HttpStatus.OK).body(tokenService.generateToken(cust));
    }
}
