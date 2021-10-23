package com.spring.security.user.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.user.model.AppUser;
import com.spring.security.user.model.Role;
import com.spring.security.user.service.AppUserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class UserController {

    private final AppUserService appUserService;


    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getUsers() {
        log.info("Get all users");
        List<AppUser> users = appUserService.getAllUsers();
        return ResponseEntity.ok(users);
    }


    @PostMapping("/users")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
        log.info("create a new  user");
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/users").toUriString());
        AppUser appUser = appUserService.saveUser(user);
        return ResponseEntity.created(uri).body(appUser);
    }


    @PostMapping("/roles")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        log.info("create a new role");
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/roles").toUriString());
        Role createdRole = appUserService.saveRole(role);
        return ResponseEntity.created(uri).body(createdRole);
    }


    @PostMapping("/new/roles")
    public ResponseEntity<?> assignRoleToUser(@RequestBody RoleToUserForm form) {
        log.info("create a new role");
        appUserService.assignRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }


    @PostMapping("token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authorization = request.getHeader("Authorization");

        if (authorization != null && authorization.startsWith("Bearer ")) {
            try {
                String refreshToken = authorization.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("$2a$12$8CnRjf.8F9jQjeeqQIL3rOkVYX2KGzE6c62CHoLkcgdBBumvUF8Yy".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refreshToken);
                String username = decodedJWT.getSubject();
                AppUser user = appUserService.getUser(username);
                String accessToken = JWT.create().withSubject(user.getUsername())
                        .withIssuedAt(new Date())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> token = new HashMap<>();
                token.put("access-token", accessToken);
                token.put("refresh-token", refreshToken);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), token);

            } catch (Exception e) {
                response.setHeader("error", e.getMessage());
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                Map<String, String> token = new HashMap<>();
                token.put("error", e.getMessage());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), token);
            }
        } else {
            log.error(" refresh token is missing ");
            throw new RuntimeException("refresh token is missing");
        }


    }

    @Data
    class RoleToUserForm {
        private String username;
        private String roleName;
    }
}


