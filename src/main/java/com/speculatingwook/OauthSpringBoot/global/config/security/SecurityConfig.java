package com.speculatingwook.OauthSpringBoot.global.config.security;

import com.speculatingwook.OauthSpringBoot.domain.login.oauth.entity.RoleType;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.exception.RestAuthenticationEntryPoint;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.filter.TokenAuthenticationFilter;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.handler.OAuth2AuthenticationFailureHandler;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.handler.OAuth2AuthenticationSuccessHandler;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.handler.TokenAccessDeniedHandler;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.service.CustomOAuth2UserService;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.service.CustomUserDetailsService;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.token.AuthTokenProvider;
import com.speculatingwook.OauthSpringBoot.domain.login.repository.user.UserRefreshTokenRepository;
import com.speculatingwook.OauthSpringBoot.global.config.properties.AppProperties;
import com.speculatingwook.OauthSpringBoot.global.config.properties.CorsProperties;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig{
    private final CorsProperties corsProperties;
    private final AppProperties appProperties;
    private final AuthTokenProvider tokenProvider;
    private final CustomUserDetailsService userDetailsService;
    private final UserRefreshTokenRepository userRefreshTokenRepository;
    private final TokenAccessDeniedHandler tokenAccessDeniedHandler;
    private final CustomOAuth2UserService oAuth2UserService;
    private static final String[] PERMIT_URL_ARRAY = {
            /* swagger v2 */
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/webjars/**",
            /* swagger v3 */
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-resources/**",
            "/signin",
            "/user/duplicate-id",
            "/user/signUp"
    };

    /*
     * security 설정 시, 사용할 인코더 설정
     * */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .cors()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable().userDetailsService(userDetailsService)
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                .accessDeniedHandler(tokenAccessDeniedHandler)
                .and()
                .authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers(PERMIT_URL_ARRAY).permitAll()
                .antMatchers("/api/**").hasAnyAuthority(RoleType.USER.getCode())
                .antMatchers("/api/**/admin/**").hasAnyAuthority(RoleType.ADMIN.getCode())
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository())
                .and()
                .redirectionEndpoint()
                .baseUri("/*/oauth2/code/*")
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler())
                .failureHandler(oAuth2AuthenticationFailureHandler());
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    /*
     * Oauth 인증 성공 핸들러
     * */
    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(
                tokenProvider,
                appProperties,
                userRefreshTokenRepository,
                oAuth2AuthorizationRequestBasedOnCookieRepository()
        );
    }

    /*
     * Oauth 인증 실패 핸들러
     * */
    @Bean
    public OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
        return new OAuth2AuthenticationFailureHandler(oAuth2AuthorizationRequestBasedOnCookieRepository());
    }


    /*
     * Cors 설정
     * */
    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource corsConfigSource = new UrlBasedCorsConfigurationSource();

        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedHeaders(Arrays.asList(corsProperties.getAllowedHeaders().split(",")));
        corsConfig.setAllowedMethods(Arrays.asList(corsProperties.getAllowedMethods().split(",")));
        corsConfig.setAllowedOrigins(Arrays.asList(corsProperties.getAllowedOrigins().split(",")));
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(corsConfig.getMaxAge());

        corsConfigSource.registerCorsConfiguration("/**", corsConfig);
        return corsConfigSource;
    }

    /*
     * auth 매니저 설정
     * */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }


    /*
     * 토큰 필터 설정
     * */
    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }

    /*
     * 쿠키 기반 인가 Repository
     * 인가 응답을 연계 하고 검증할 때 사용.
     * */
    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }
}