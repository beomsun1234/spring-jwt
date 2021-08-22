package com.bs.hellojwt.controller.dto;

import lombok.Data;

@Data
public class LoginForm {

    private String email;

    private String password;
}
