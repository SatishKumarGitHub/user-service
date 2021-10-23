package com.spring.security.user;

import com.spring.security.user.model.AppUser;
import com.spring.security.user.model.Role;
import com.spring.security.user.service.AppUserService;
import org.omg.CosNaming._BindingIteratorImplBase;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    CommandLineRunner run(AppUserService userService) {
        return args -> {

            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new AppUser(null, "Mahesh kanthasamy", "mahesh", "mahesh123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Satish kanthasamy", "satish", "satish123", new ArrayList<>()));
            userService.saveUser(new AppUser(null, "Madhavan Sankaran", "madhavan", "madhavan123", new ArrayList<>()));

            userService.assignRoleToUser("mahesh", "ROLE_SUPER_ADMIN");
            userService.assignRoleToUser("mahesh", "ROLE_USER");
            userService.assignRoleToUser("mahesh", "ROLE_MANAGER");
            userService.assignRoleToUser("satish", "ROLE_ADMIN");
            userService.assignRoleToUser("satish", "ROLE_USER");
            userService.assignRoleToUser("madhavan", "ROLE_USER");

        };
    }

}
