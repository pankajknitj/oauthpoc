package com.example.practice_ss.exception;

public class AppAuthenticationException extends RuntimeException{

    public AppAuthenticationException(String msg){
        super(msg);
    }
}
