package com.bs.hellojwt.controller;

import com.bs.hellojwt.auth.SecurityUser;
import com.bs.hellojwt.controller.dto.UserInfoDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("api")
public class UserApiController {


    @GetMapping("/v1/user")
    public UserInfoDto user(Authentication authentication){
        log.info("ROLE_USER  AND    ADMIN");
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        UserInfoDto userInfo = UserInfoDto.builder()
                .id(user.getUser().getId())
                .email(user.getEmail())
                .name(user.getUsername())
                .role(user.getUser().getRole())
                .build();
        return userInfo;
    }
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/v1/admin")
    public UserInfoDto admin(Authentication authentication){
        log.info("Only ADMIN");
        SecurityUser user = (SecurityUser) authentication.getPrincipal();
        UserInfoDto userInfo = UserInfoDto.builder()
                .id(user.getUser().getId())
                .email(user.getEmail())
                .name(user.getUsername())
                .role(user.getUser().getRole())
                .build();
        return userInfo;
    }

}
