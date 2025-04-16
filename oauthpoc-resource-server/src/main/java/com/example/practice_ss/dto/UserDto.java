package com.example.practice_ss.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class UserDto {
    private String userName;
    private String password;
    private String authority;
}
