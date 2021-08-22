package com.bs.hellojwt.config;

import com.bs.hellojwt.domain.user.UserRepository;
import com.bs.hellojwt.jwt.JwtAuthenticationFilter;
import com.bs.hellojwt.jwt.JwtAuthorizationFilter;
import com.bs.hellojwt.jwt.JwtEntryPoint;
import com.bs.hellojwt.util.CookieUtil;
import com.bs.hellojwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CookieUtil cookieUtil;
    private final ObjectMapper objectMapper;
    //private final Myfilter1 myfilter1;
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final JwtEntryPoint jwtEntryPoint;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager(),objectMapper,jwtUtil,cookieUtil))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository,jwtUtil,cookieUtil))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();



        //http.addFilterBefore(myfilter1, UsernamePasswordAuthenticationFilter.class);
    }
}
