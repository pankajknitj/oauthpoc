package com.example.practice_ss.repo;

import com.example.practice_ss.model.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CustomerRepo extends JpaRepository<Customer,Long> {
    public List<Customer> findByEmail(String email);
}
