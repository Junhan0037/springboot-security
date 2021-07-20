package com.springcoresecurity.security.domain;

import com.springcoresecurity.domain.entity.Account;
import com.sun.istack.NotNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

public class UserDto implements Serializable, UserDetails {

    private Account account;
    private List<String > roles;

    public UserDto(Account account, List<String> roles) {
        this.account = account;
        this.roles = roles;
    }

    @NotNull
    private String username;

    private String password;

    private Integer role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
