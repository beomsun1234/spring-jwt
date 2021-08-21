package com.bs.hellojwt;

import com.bs.hellojwt.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@RequiredArgsConstructor
@SpringBootApplication
public class HelloJwtApplication {

	public static void main(String[] args) {

		SpringApplication.run(HelloJwtApplication.class, args);
	}

}
