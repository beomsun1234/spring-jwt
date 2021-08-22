package com.bs.hellojwt.controller;


import com.bs.hellojwt.controller.dto.UserJoinDto;
import com.bs.hellojwt.domain.user.Role;
import com.bs.hellojwt.domain.user.User;
import com.bs.hellojwt.domain.user.UserRepository;
import com.bs.hellojwt.util.CookieUtil;
import com.bs.hellojwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@Slf4j
@RestController
@RequiredArgsConstructor
public class HomeController {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    private final CookieUtil cookieUtil;
    @GetMapping("/")
    public String home(HttpServletRequest request){
        String token = cookieUtil.getCookie(request, JwtUtil.ACCESS_TOKEN_NAME).getValue();
        if(token != null){
            log.info("token={}",token);
            return "access_token="+token;
        }
        return "토큰없음";
    }

    @PostMapping("/token")
    public String token(){
        return "<h1>token</h1>";
    }
    @PostMapping("/v1/join")
    public User join(@RequestBody UserJoinDto user){
        log.info("회원가입진행");
        log.info("pass={}",user.getPassword());
        String password = bCryptPasswordEncoder.encode(user.getPassword());
        log.info("endcodepass={}",password);
        User test = User.builder()
                .email(user.getEmail())
                .name(user.getName())
                .password(password)
                .role(Role.ROLE_USER)
                .build();
        return userRepository.save(test);
    }
}
