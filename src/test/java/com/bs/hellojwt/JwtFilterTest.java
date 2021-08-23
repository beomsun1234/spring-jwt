package com.bs.hellojwt;

import com.bs.hellojwt.controller.dto.LoginUserDto;
import com.bs.hellojwt.controller.dto.UserInfoDto;
import com.bs.hellojwt.jwt.TokenDto;
import com.bs.hellojwt.util.CookieUtil;
import com.bs.hellojwt.util.JwtUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.mock.http.server.reactive.MockServerHttpRequest.post;

@ActiveProfiles("test")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class JwtFilterTest {
    @Autowired
    private HttpServletRequest servletRequest;
    @Autowired
    private CookieUtil cookieUtil;
    @Autowired
    private ObjectMapper objectMapper;
    private RestTemplate restTemplate=new RestTemplate();
    @Autowired
    private JwtUtil jwtUtil;
    @LocalServerPort
    private int port;

    private URI uri(String path) throws URISyntaxException {
        return new URI(format("http://localhost:%d%s",port,path));
    }
    @DisplayName("1. jwt로 로그인을 시도 후 성공하면 바디에 토큰이 발급된다")
    @Test
    void test_1() throws URISyntaxException, JsonProcessingException {
        //given
        LoginUserDto userDto = LoginUserDto.builder().email("admin").password("1234").build();
        HttpEntity<LoginUserDto> body = new HttpEntity<>(userDto);

        //when
        ResponseEntity<String> token = restTemplate.exchange(uri("/login"), HttpMethod.POST, body, String.class);

        //then
        Assertions.assertEquals(200,token.getStatusCodeValue());
        System.out.println("token="+token.getBody());
    }

    @DisplayName("2. 룰이 user인 토큰이면 user 페이지에 접근할 수 있다")
    @Test
    void test_2() throws URISyntaxException, JsonProcessingException {

        //given
        String access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InRlc3QiLCJpZCI6MSwibmFtZSI6InBhcmsiLCJpYXQiOjE2Mjk3MTY1NjcsImV4cCI6MTYyOTcxNzE2N30.kjdjVHM1udmuLhrU2-PJ4etHp1CA6fCj7V5CVgNSJkQ";
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization","Bearer "+access_token);
        HttpEntity<String> header = new HttpEntity<>(httpHeaders);
        //when
        ResponseEntity<String> responseEntity = restTemplate.exchange(uri("/api/v1/user"), HttpMethod.GET, header, String.class);

        //then
        Assertions.assertEquals(200,responseEntity.getStatusCodeValue());
    }

    @DisplayName("3. 룰이 user인 토큰이면 admin 페이지에 접근할 수 없다 403에러")
    @Test
    void test_3() throws URISyntaxException, JsonProcessingException {

        //given
        String user_access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InRlc3QiLCJpZCI6MSwibmFtZSI6InBhcmsiLCJpYXQiOjE2Mjk3MTY1NjcsImV4cCI6MTYyOTcxNzE2N30.kjdjVHM1udmuLhrU2-PJ4etHp1CA6fCj7V5CVgNSJkQ";
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization","Bearer "+user_access_token);
        HttpEntity<String> header = new HttpEntity<>(httpHeaders);

        //when //then
        assertThrows(HttpClientErrorException.class,()->{
                    ResponseEntity<UserInfoDto> responseEntity = restTemplate.exchange(uri("/api/v1/admin"), HttpMethod.GET, header, UserInfoDto.class);
                }
                );
    }

    @DisplayName("4. 룰이 admin인 토큰이면 user 페이지에 접근할 수 있다.")
    @Test
    void test_4() throws URISyntaxException, JsonProcessingException {

        //given
        String admin_access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImFkbWluIiwiaWQiOjMzLCJuYW1lIjoiYWRtaW4iLCJpYXQiOjE2Mjk3MTc1NjEsImV4cCI6MTYyOTcxODE2MX0.UuT3e3PrKVK-uu6-RiP5HGr3mzXja2XHRw765IjVqRo";
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization","Bearer "+admin_access_token);
        HttpEntity<String> header = new HttpEntity<>(httpHeaders);

        //when
        ResponseEntity<UserInfoDto> responseEntity = restTemplate.exchange(uri("/api/v1/admin"), HttpMethod.GET, header, UserInfoDto.class);
        //then
        Assertions.assertEquals(200,responseEntity.getStatusCodeValue());
    }

    @DisplayName("4. 룰이 admin인 토큰이면 admin 페이지에 접근할 수 있다.")
    @Test
    void test_5() throws URISyntaxException, JsonProcessingException {
        //given
        String admin_access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImFkbWluIiwiaWQiOjMzLCJuYW1lIjoiYWRtaW4iLCJpYXQiOjE2Mjk3MTc1NjEsImV4cCI6MTYyOTcxODE2MX0.UuT3e3PrKVK-uu6-RiP5HGr3mzXja2XHRw765IjVqRo";
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization","Bearer "+admin_access_token);
        HttpEntity<String> header = new HttpEntity<>(httpHeaders);

        //when
        ResponseEntity<UserInfoDto> responseEntity = restTemplate.exchange(uri("/api/v1/user0"), HttpMethod.GET, header, UserInfoDto.class);
        //then
        Assertions.assertEquals(200,responseEntity.getStatusCodeValue());
    }
}
