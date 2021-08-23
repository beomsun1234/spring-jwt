package com.bs.hellojwt;

import com.bs.hellojwt.auth.SecurityUser;
import com.bs.hellojwt.controller.dto.UserInfoDto;
import com.bs.hellojwt.domain.user.Role;
import com.bs.hellojwt.util.JwtUtil;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;


import static org.junit.jupiter.api.Assertions.assertThrows;


@SpringBootTest
public class JwtTokenTest {

    @Autowired
    private JwtUtil jwtUtil;



    @DisplayName("Jwt토큰 생성 후 해당 토큰에 들어있는 이메일과 내가 입력한 이메일이 같은지 확인")
    @Test
    void jwt토큰생성(){
        UserInfoDto infoDto = UserInfoDto.builder().role(Role.ROLE_USER).name("park").email("park").id(1L).build();
        String token = jwtUtil.generateToken(infoDto);

        String email = jwtUtil.getEmail(token);

        Assertions.assertThat(email).isEqualTo("park");
    }

    @DisplayName("3초가 지나면 토큰이 유효하지 않다.")
    @Test
    void jwt유효기간() throws InterruptedException {

        //given
        UserInfoDto infoDto = UserInfoDto.builder().role(Role.ROLE_USER).name("park").email("park").id(1L).build();
        String token = jwtUtil.generateToken(infoDto);

        //when
        Thread.sleep(4000);

        //given
        assertThrows(Exception.class,()->{
            Assertions.assertThat(jwtUtil.isTokenExpired(token));
        });

    }



}
