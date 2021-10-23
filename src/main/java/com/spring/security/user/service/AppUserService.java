package com.spring.security.user.service;

import com.spring.security.user.model.AppUser;
import com.spring.security.user.model.Role;

import java.util.List;

public interface AppUserService {

    AppUser saveUser(AppUser user);

    Role saveRole(Role role);

    void assignRoleToUser(String username, String roleName);

    AppUser getUser(String username);

    List<AppUser> getAllUsers();
}
