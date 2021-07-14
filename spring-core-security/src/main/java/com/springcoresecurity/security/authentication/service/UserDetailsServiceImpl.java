package com.springcoresecurity.security.authentication.service;

import com.springcoresecurity.domain.entity.Account;
import com.springcoresecurity.domain.entity.Role;
import com.springcoresecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);

        if (account == null && userRepository.countByUsername(username) == 0) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        Set<String> userRoles = account.getUserRoles().stream().map(Role::getRoleName).collect(Collectors.toSet());
        List<GrantedAuthority> collect = userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        return new AccountContext(account, collect);
    }

}
