package com.bs.hellojwt.jwt;

import com.bs.hellojwt.auth.SecurityUser;
import com.bs.hellojwt.controller.dto.LoginForm;
import com.bs.hellojwt.controller.dto.UserInfoDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import java.io.PrintWriter;
import java.util.Date;


/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
 * login 요청해서 username, password 전송하면(post)
 * UsernamePasswordAuthenticationFilter가 동작함
 * */


@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,ObjectMapper objectMapper, JwtUtil jwtUtil){
        this.authenticationManager = authenticationManager;
        this.objectMapper = objectMapper;
        this.jwtUtil =  jwtUtil;
    }
    //@Value("${jwttest.secret-key}")
    private String secret= "qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
    /**
     * /login 요청오면 실행되는 함수
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("로그인시도중");
        /**
         * 1.useremail, password 받아서
         * 2.정상인지 로그인시도 해봄. authenticationManager로 로그인시도를 하면 CustomUserDetailsService가 호출된다
         * 3. securityUser를 세션에 담고
         * 4. jwt 토큰을 만들어 응답
         */
        //1
        try {
            LoginForm loginUser = objectMapper.readValue(request.getInputStream(), LoginForm.class);
            log.info("email={}", loginUser.getEmail());
            log.info("pass={}", loginUser.getPassword());
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser.getEmail(), loginUser.getPassword());
            //  CustomUserDetailsService의 loadByUsername() 함수가 실행된다(나는 email로 호출한다)
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            // authentication 객체가 세션영역에 저장됨 => 로그인이 되었다는 뜻
            //SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
            log.info("-----------로그인완료됨");
            //log.info("email={}", securityUser.getEmail());
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다
    // jwt 토큰으 ㄹ만들어서 request요청한 사용자에게 jwt토큰을 reponse해주면된다
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("인증이완료되었습니다---");
        SecurityUser user = (SecurityUser)authResult.getPrincipal();
        UserInfoDto userInfo = UserInfoDto.builder()
                .id(user.getUser().getId())
                .name(user.getUsername())
                .email(user.getEmail())
                .role(user.getUser().getRole())
                .build();
        log.info(" ----토큰발급-------");
        String access_token =jwtUtil.generateToken(userInfo);
        String refresh_token = jwtUtil.generateRefreshToken(userInfo);

        response.addHeader("Authorization", "Bearer "+access_token);
        response.addHeader("refreshToken ", "Bearer "+refresh_token);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        PrintWriter printWriter = response.getWriter();
        printWriter.print(objectMapper.writeValueAsString(jwtUtil.tokenToDto(access_token,refresh_token)));
        printWriter.flush();

    }
    /**
     * 이메일 ,패스워드 로그인 정상
     * 서버쪽 세션 ID 생성
     * 클라이언트 쿠키로 세션 ID를 응답
     * 요청할 때마다 쿠키값 세션ID를 항상 들고 서버쪽으로 요청하기 때문에
     * 서버는 세션ID가 유요한지 판다해서 유요하면 인증이 필요한 페이지로 접근하게 하면된다,
     *
     * 1.이메일, 패스워드 로그인정상
     * 2. jwt토큰생성
     * 3. 클라이언트 쪽으로 JWT 토큰 응답
     * 4. 요청할때마다 jwt토큰을 가지고 요청
     * 5. 서버는 JWT토큰이 유효한지를 판단
     */
}
