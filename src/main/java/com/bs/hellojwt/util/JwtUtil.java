package com.bs.hellojwt.util;

import com.bs.hellojwt.auth.SecurityUser;
import com.bs.hellojwt.controller.dto.UserInfoDto;
import com.bs.hellojwt.jwt.TokenDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.net.http.HttpHeaders;
import java.util.Date;

@Component
public class JwtUtil {
    public final static long TOKEN_VALIDATION_SECOND = 1000L * 60; //10분
    public final static long REFRESH_TOKEN_VALIDATION_SECOND = 1000L * 60 * 24 * 2;
    private String secret= "qkrqjatjs12345678910111231231232131232131231231231231231232131231231231245";
    final static public String ACCESS_TOKEN_NAME = "accessToken";
    final static public String REFRESH_TOKEN_NAME = "refreshToken";

    /**
     * String access_token = Jwts.builder().setSubject("cos_token")
     *             .setExpiration(new Date(System.currentTimeMillis()+(60000*10)))
     *             .claim("id",userInfo.getId())
     *             .claim("email", userInfo.getEmail())
     *             .claim("name", userInfo.getName())
     *             .signWith(SignatureAlgorithm.HS256, secret.getBytes())
     *             .compact();
     */

    /**
     * 토큰이 유효한 토큰인지 검사한 후, 토큰에 담긴 Payload 값을 가져온다.
     */
    public Claims extractAllClaims(String token) throws ExpiredJwtException {
        return Jwts.parserBuilder()
                .setSigningKey(secret.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * if (claims.get("email",String.class) !=null){
     *             log.info("토큰검증 통과");
     *             User user = userRepository.findByEmail(claims.get("email", String.class)).orElseThrow(()->new IllegalArgumentException("찾는 이메일이 없습니다."));
     *             SecurityUser securityUser = new SecurityUser(user);
     *             //jwt토큰 서명을 통해 서명이 정상이면 Authentication객체를만들어준다
     *             Authentication authentication = new UsernamePasswordAuthenticationToken(securityUser,null,securityUser.getAuthorities());
     *             //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
     *             SecurityContextHolder.getContext().setAuthentication(authentication);
     *             chain.doFilter(request,response);
     * @param token
     * @return
     */
    public String getEmail(String token) {
        return extractAllClaims(token).get("email", String.class);
    }

    /*
    isTokenExpired() : 토큰이 만료됐는지 안됐는지 확인.
     */
    public Boolean isTokenExpired(String token) {
        final Date expiration = extractAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    public String generateToken(UserInfoDto user) {
        return doGenerateToken(user, TOKEN_VALIDATION_SECOND);
    }

    /**
     * 토큰을 생성, 페이로드에 담길 값은 userInfo
     * @param userInfoDto
     * @param expireTime
     * @return
     */
    private String doGenerateToken(UserInfoDto userInfoDto, long expireTime) {

        Claims claims = Jwts.claims();
        claims.put("email", userInfoDto.getEmail());
        claims.put("id", userInfoDto.getId());
        claims.put("name", userInfoDto.getName());

        String jwt = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();

        return jwt;
    }

    public String generateRefreshToken(UserInfoDto user) {
        return doGenerateToken(user, REFRESH_TOKEN_VALIDATION_SECOND);
    }

    public Boolean validateToken(String token, SecurityUser user) {
        final String email = getEmail(token);
        return (email.equals(user.getEmail()) && ! isTokenExpired(token));
    }

    public TokenDto tokenToDto(String accessToken, String refreshToken){
        return TokenDto.builder().access_token(accessToken).refresh_token(refreshToken).build();
    }

    public String extractHeader(String headerJwt){
        return headerJwt.substring(7);
    }


    /**
     * doGenerateToken() : 토큰을 생성, 페이로드에 담길 값은 email
     * extractAllclaims() : 토큰이 유효한 토큰인지 검사한 후, 토큰에 담긴 Payload 값을 가져온다.
     * getUsername() : 추출한 Payload로부터 userName을 가져온다.
     * isTokenExpired() : 토큰이 만료됐는지 안됐는지 확인.
     * geneate~~Token() : Access/Refresh Token을 형성
     */


}
