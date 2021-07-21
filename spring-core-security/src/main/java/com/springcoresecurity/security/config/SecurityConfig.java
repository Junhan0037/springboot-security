package com.springcoresecurity.security.config;

import com.springcoresecurity.security.authentication.handler.CommonAccessDeniedHandler;
import com.springcoresecurity.security.authentication.handler.FormAuthenticationFailureHandler;
import com.springcoresecurity.security.authentication.handler.FormAuthenticationSuccessHandler;
import com.springcoresecurity.security.authentication.provider.FormAuthenticationProvider;
import com.springcoresecurity.security.authentication.service.FormWebAuthenticationDetailsSource;
import com.springcoresecurity.security.metaDataSource.UrlSecurityMetadataSource;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final FormAuthenticationProvider authenticationProvider;
    private final FormWebAuthenticationDetailsSource authenticationDetailsSource;
    private final FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    private final FormAuthenticationFailureHandler formAuthenticationFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/users", "/user/login/**", "/login**").permitAll()
                .anyRequest().authenticated()

        .and().formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll()

        .and().exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())

        .and().addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CommonAccessDeniedHandler accessDeniedHandler = new CommonAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Bean
    public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
        filterSecurityInterceptor.setSecurityMetadataSource(urlSecurityMetadataSource());
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        return filterSecurityInterceptor;
    }

    private AccessDecisionManager affirmativeBased() {
        return new AffirmativeBased(getAccessDecisionVoters());
    }

    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        return Arrays.asList(new RoleVoter());
    }

    @Bean
    public FilterInvocationSecurityMetadataSource urlSecurityMetadataSource() {
        return new UrlSecurityMetadataSource();
    }

}
