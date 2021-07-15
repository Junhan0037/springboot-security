package com.springcoresecurity.security.token;

import com.springcoresecurity.security.domain.UserDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AjaxAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public AjaxAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    public static AjaxAuthenticationToken getTokenFromAccountContext(UserDto userDto) {
        return new AjaxAuthenticationToken(userDto, userDto.getPassword(), userDto.getAuthorities());
    }

}
