package com.bs.hellojwt.controller;

import com.bs.hellojwt.auth.SecurityUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("api")
public class UserApiController {

    @GetMapping("/v1/user")
    public SecurityUser user(Authentication authentication){
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        log.info("userId={}",user.getUser().getId());
        log.info("userName={}",user.getUsername());
        log.info("userEmail={}",user.getEmail());
        return user;
    }
    @GetMapping("/v1/admin")
    public String admin(){
        return "admin";
    }

}
