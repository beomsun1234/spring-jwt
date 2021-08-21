package com.bs.hellojwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowCredentials(true)
                .allowedOriginPatterns("*")
                .allowedMethods("*")
                .allowedHeaders("*");
        // cors오린진(인증x)
    }
    /**
     * 스프링부트에서 CORS 설정할 때 .allowCredentials(true)와 .allowedOrigins("*")는 동시에 설정 못하도록 업데이트되었다고 함. 모든 주소를 허용하는 대신 특정 패턴만 허용하는 것으로 적용해야한다고 변동되었음. .allowedOrigins("*") 대신 .allowedOriginPatterns("*")를 사용하면 에러는 해결이 된다.
     */
}
