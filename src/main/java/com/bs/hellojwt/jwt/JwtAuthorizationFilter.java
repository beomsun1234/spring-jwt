package com.bs.hellojwt.jwt;

import com.bs.hellojwt.auth.SecurityUser;
import com.bs.hellojwt.controller.dto.UserInfoDto;
import com.bs.hellojwt.domain.user.User;
import com.bs.hellojwt.domain.user.UserRepository;
import com.bs.hellojwt.util.CookieUtil;
import com.bs.hellojwt.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticatrionFilter라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 위 필터를 무조건 타게되어있다
// 만약 권한이나 인증이 필요한 주소가 아니라면 필터를 안탄다
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    //@Value("${jwt.secret-key}")
    private String secret="qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
    private final JwtUtil jwtUtil;
    private final CookieUtil cookieUtil;
    private final UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository,JwtUtil jwtUtil,CookieUtil cookieUtil) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.cookieUtil = cookieUtil;
    }

    /**
     * 시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticatrionFilter라는 것이 있다.
     * 권한이나 인증이 필요한 특정 주소를 요청했을 위 필터를 무조건 타게되어있다
     * 만약 권한이나 인증이 필요한 주소가 아니라면 필터를 안탄다
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        Cookie cookie = cookieUtil.getCookie(request, JwtUtil.ACCESS_TOKEN_NAME);
        String jwtHeader = request.getHeader("Authorization");
        String header = request.getHeader("refreshToken"); //
        log.info("header={}",header);
        String refreshToken =null;
        // 헤더가 있는지 확인
        if( cookie == null){
            chain.doFilter(request,response);
            log.info("헤더에 jwt토큰 없음");
            return;
        }
        /**
         * test용도이다 밑에는
         */
//        if( jwtHeader == null || !jwtHeader.startsWith("Bearer")){
//            chain.doFilter(request,response);
//            log.info("헤더에 jwt토큰 없음");
//            return;
//        }
        try {
            //String jwtToken = jwtHeader.substring(7); --테스트용
            String jwtToken = cookie.getValue();
            String email = jwtUtil.getEmail(jwtToken);
            if (email != null){
                log.info("토큰검증 통과");
                User user = userRepository.findByEmail(email).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
                SecurityUser securityUser = new SecurityUser(user);
                if (jwtUtil.validateToken(jwtToken,securityUser)){
                    //jwt토큰 서명을 통해 서명이 정상이면 Authentication객체를만들어준다
                    log.info("유요한토큰입니다");
                    Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
                    //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }catch (ExpiredJwtException e){
            log.info("토큰유효기간만료됨");
            log.info("refresh_cookie에서 refreshToken가져와라");
            Cookie refresh_cookie = cookieUtil.getCookie(request,JwtUtil.REFRESH_TOKEN_NAME);

            if(refresh_cookie!=null){
                log.info("refresh_cookie에서 refreshToken이 존재한다");
                refreshToken = refresh_cookie.getValue();
                log.info("refreshToken={}",refreshToken);
            }
        } catch (Exception e){
        }
        try{
            if(refreshToken != null){
                String email = jwtUtil.getEmail(refreshToken);
                log.info("email={}",email);
                if(email.equals(jwtUtil.getEmail(refreshToken))){
                    User user = userRepository.findByEmail(email).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
                    SecurityUser securityUser = new SecurityUser(user);
                    Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
                    //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
                    UserInfoDto userInfo = UserInfoDto.builder()
                            .id(securityUser.getUser().getId())
                            .name(securityUser.getUsername())
                            .email(securityUser.getEmail())
                            .role(securityUser.getUser().getRole())
                            .build();
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    String newToken =jwtUtil.generateToken(userInfo);
                    response.addCookie(cookieUtil.createCookie(JwtUtil.ACCESS_TOKEN_NAME,newToken));

                }
            }
        }catch(ExpiredJwtException e){
            log.info("refreshToken 만료됨");
            log.info("다시 로그인 해주세요");
        }
        chain.doFilter(request,response);
    }
}
