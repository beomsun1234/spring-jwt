package com.bs.hellojwt.auth;

import com.bs.hellojwt.domain.user.User;
import com.bs.hellojwt.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


/**
 * http://localhost:8080/login요청이 올떄 동작한다
 */

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("CustomUserDetailsService loadUserByUsername 실행");
        User user = userRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("이메일이 없습니다"));
//        log.info("useremail={}",user.getEmail());
//        log.info("useremail={}",new SecurityUser(user).getEmail());
//        log.info("useremail={}",new SecurityUser(user).getUsername());
        return new SecurityUser(user);


    }
}
