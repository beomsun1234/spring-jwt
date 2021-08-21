package com.bs.hellojwt.domain.user;

import lombok.Data;

@Data
public class LoginForm {
    private String name;

    private String email;

    private String password;
}
