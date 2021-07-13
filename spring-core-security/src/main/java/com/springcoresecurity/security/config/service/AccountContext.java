package com.springcoresecurity.security.config.service;

import com.springcoresecurity.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, List<GrantedAuthority> roles) {
        super(account.getUsername(), account.getPassword(), roles);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }

}
