package com.bs.hellojwt.controller.dto;

import lombok.Data;

@Data
public class LoginUserDto {

    private String email;

    private String password;
}
