package com.spring.security.user.service;

import com.spring.security.user.model.AppUser;
import com.spring.security.user.model.Role;
import com.spring.security.user.repository.AppUserRepository;
import com.spring.security.user.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AppUserServiceImpl implements AppUserService, UserDetailsService {

    private final AppUserRepository appUserRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<AppUser> optional = appUserRepository.findByUsername(username);
        if (optional.isPresent()) {
            AppUser user = optional.get();
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            user.getRoles().forEach(r -> authorities.add(new SimpleGrantedAuthority(r.getName())));
            return new User(user.getUsername(), user.getPassword(), authorities);
        } else {
            log.error("User not found in the system...");
            throw new UsernameNotFoundException("User with " + username + " not found");
        }

    }

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("saving new user {} to database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return appUserRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role {} to database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void assignRoleToUser(String username, String roleName) {
        Optional<AppUser> optional = appUserRepository.findByUsername(username);
        if (optional.isPresent()) {
            log.info("assigning new role {} to user {} ", roleName, username);
            AppUser appUser = optional.get();
            Role role = roleRepository.findByName(roleName);
            appUser.getRoles().add(role);
        }
    }

    @Override
    public AppUser getUser(String username) {
        log.info("Get a user {} ", username);
        return appUserRepository.findByUsername(username).orElse(new AppUser());
    }

    @Override
    public List<AppUser> getAllUsers() {
        log.info("Get all users");
        return appUserRepository.findAll();
    }


}
