package com.example.practice_ss.service;

import com.example.practice_ss.model.Customer;

public interface TokenService {

    public String generateToken(Customer customer);
}
