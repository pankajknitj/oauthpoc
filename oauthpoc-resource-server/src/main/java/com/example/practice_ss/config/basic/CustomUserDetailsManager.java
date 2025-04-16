package com.example.practice_ss.config.basic;

import com.example.practice_ss.model.Customer;
import com.example.practice_ss.repo.CustomerRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

import static com.example.practice_ss.constans.ApplicationConstants.BASIC_AUTH;

@Profile(BASIC_AUTH)
@Component
public class CustomUserDetailsManager implements UserDetailsManager {
    @Autowired
    private CustomerRepo customerRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void createUser(UserDetails user) {
        if(userExists(user.getUsername())){
            throw new RuntimeException("user already exists");
        }
        Customer customer = new Customer();
        customer.setEmail(user.getUsername());
        customer.setPwd(passwordEncoder.encode(user.getPassword()));
        customer.setRole(String.valueOf(user.getAuthorities().stream().findFirst().orElse(null)));
        customerRepo.save(customer);
    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return !customerRepo.findByEmail(username).isEmpty();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer = customerRepo.findByEmail(username).stream().findFirst().orElse(null);
        if(customer == null){
            throw new UsernameNotFoundException("user is not registered");
        }

        List<SimpleGrantedAuthority> authorities = Arrays.stream(customer.getRole().split(","))
                .map(String::trim)
                .map(SimpleGrantedAuthority::new)
                .toList();

        return User.withUsername(customer.getEmail())
                .password(customer.getPwd())
                .authorities(authorities)
                .build();
    }
}
