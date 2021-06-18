package com.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN") // 구체적인 경로를 먼저 선언
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.exceptionHandling()
                .authenticationEntryPoint((request, response, e) -> response.sendRedirect("/login")) // 인증예외
                .accessDeniedHandler((request, response, e) -> response.sendRedirect("/denied")); // 인가예외

        http.formLogin()
                .loginPage("/loginPage") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/loginPage") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정
                .passwordParameter("passwd") // 비밀번호 파라미터명 설정
                .loginProcessingUrl("/login_prod") // 로그인 Form Action Url
                .successHandler((request, response, authentication) -> { // 로그인 성공 후 핸들러
                    System.out.println("authentication : " + authentication.getName());
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception) -> { // 로그인 실패 후 핸들러
                    System.out.println("exception : " + exception.getMessage());
                    response.sendRedirect("/loginPage");
                })
                .permitAll(); // 해당 경로들 통과

        http.logout()
                .logoutUrl("/logout") // 로그아웃 처리 URL
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동페이지
                .deleteCookies("JSESSIONID", "remember-me") // 로그아웃 후 해당 쿠키 삭제
                .addLogoutHandler((request, response, authentication) -> { // 로그아웃 핸들러
                    HttpSession session = request.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login")); // 로그아웃 성공 후 핸들러

        http.rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // Default 14일 (초단위)
                .alwaysRemember(true) // 기억하기 기능이 활성화되지 않아도 항상 실행 (Default false)
                .userDetailsService(userDetailsService); // 사용자 계정 조회 (필수)

        http.sessionManagement()
                .maximumSessions(1) // 최대 허용 세션 수, -1: 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(true) // 동시 로그인 차단함, default (false): 기존 세션 만료
                .expiredUrl("/expired"); // 세션이 만료된 경우 이동할 페이

        http.sessionManagement()
                .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 때 이동할 페이지
                .sessionFixation().changeSessionId()  // 기본값 (none), migrateSession, newSession
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 스프링 시큐리티가 필요 시 생성 (기본값)
    }

}
