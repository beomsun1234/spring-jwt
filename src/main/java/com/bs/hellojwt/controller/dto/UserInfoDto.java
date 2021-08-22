package com.bs.hellojwt.controller.dto;

import com.bs.hellojwt.domain.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserInfoDto {
    private Long id;
    private String name;
    private String email;
    private Role role;
}
