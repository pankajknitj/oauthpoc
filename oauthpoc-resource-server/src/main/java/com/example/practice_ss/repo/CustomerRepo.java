package com.example.practice_ss.repo;

import com.example.practice_ss.model.Customer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CustomerRepo extends JpaRepository<Customer,Long> {
    public List<Customer> findByEmail(String email);
}
