package com.bs.hellojwt.util;


import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@Component
public class CookieUtil {

    public Cookie createCookie(String key, String value){
        Cookie token = new Cookie(key,value);
        token.setHttpOnly(true);
        token.setMaxAge((int) JwtUtil.TOKEN_VALIDATION_SECOND);
        token.setPath("/");
        return token;
    }

    public Cookie getCookie(HttpServletRequest req, String key){
        final Cookie[] cookies = req.getCookies();
        if(cookies==null) return null;
        for(Cookie cookie : cookies){
            if(cookie.getName().equals(key))
                return cookie;
        }
        return null;
    }
    //token은 cookie 형태로 저장될 것.
    //나는 Access Token과 Refresh Token을 HttpOnly로 설정을 해두고 사용한다.
}
