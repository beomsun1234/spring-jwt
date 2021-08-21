package com.bs.hellojwt.domain.user;

import com.bs.hellojwt.domain.user.Role;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.*;


@NoArgsConstructor
@Getter
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    public User(String name, String email, String password, Role role){
        this.name=name;
        this.email = email;
        this.password = password;
        this.role = role;
    }
}
