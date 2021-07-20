package com.springcoresecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springcoresecurity.security.domain.UserDto;
import com.springcoresecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.springcoresecurity.util.WebUtil.isAjax;
import static org.thymeleaf.util.StringUtils.isEmpty;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported.");
        }

        UserDto userDto = objectMapper.readValue(request.getReader(), UserDto.class);
        if (isEmpty(userDto.getUsername()) || isEmpty(userDto.getPassword())) {
            throw new IllegalStateException("Username or Password is empty");
        }

        AjaxAuthenticationToken token = AjaxAuthenticationToken.getTokenFromAccountContext(userDto);

        return getAuthenticationManager().authenticate(token);
    }

}
