package com.example.practice_ss.exception;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.nio.file.AccessDeniedException;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(AppAuthenticationException.class)
    public ResponseEntity<?> handlerAuthenticationExp(AppAuthenticationException e){
        return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handelAccessDenied(AccessDeniedException e){
        return new ResponseEntity<>(e.getMessage(), HttpStatus.FORBIDDEN);
    }
}
