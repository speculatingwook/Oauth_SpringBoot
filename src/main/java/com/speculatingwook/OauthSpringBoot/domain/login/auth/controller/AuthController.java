package com.speculatingwook.OauthSpringBoot.domain.login.auth.controller;

import com.speculatingwook.OauthSpringBoot.domain.login.dto.request.LoginRequest;
import com.speculatingwook.OauthSpringBoot.domain.login.dto.response.AccessTokenResponse;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.entity.UserRefreshToken;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.entity.RoleType;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.repository.user.UserRefreshTokenRepository;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.repository.user.UserRepository;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.entity.UserPrincipal;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.token.AuthToken;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.token.AuthTokenProvider;
import com.speculatingwook.OauthSpringBoot.global.common.dto.ResponseHeader;
import com.speculatingwook.OauthSpringBoot.global.config.properties.AppProperties;
import com.speculatingwook.OauthSpringBoot.global.utils.CookieUtil;
import com.speculatingwook.OauthSpringBoot.global.utils.HeaderUtil;
import io.jsonwebtoken.Claims;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.Date;

@RestController
@Api(tags = "AuthController")
public class AuthController {
    AuthenticationManager authenticationManager;
    AppProperties appProperties;
    AuthTokenProvider tokenProvider;
    UserRepository userRepository;
    UserRefreshTokenRepository userRefreshTokenRepository;

    private final static long THREE_DAYS_MSEC = 259200000;
    private final static String REFRESH_TOKEN = "refresh_token";

    @ApiOperation("test")
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(
            @ApiParam(value = "test", required = true)
            HttpServletRequest request,
            HttpServletResponse response,
            @Valid @RequestBody LoginRequest loginRequest) {

        String userId = loginRequest.getUserId();
        Date now = new Date();

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUserId(),
                        loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);


        AuthToken accessToken = tokenProvider.createAuthToken(
                userId,
                ((UserPrincipal) authentication.getPrincipal()).getRoleType().getCode(),
                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
        );

        long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();
        AuthToken refreshToken = tokenProvider.createAuthToken(
                appProperties.getAuth().getTokenSecret(),
                new Date(now.getTime() + refreshTokenExpiry)
        );

        // userId refresh token 으로 DB 확인
        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserId(userId);
        if (userRefreshToken == null) {
            // 없는 경우 새로 등록
            userRefreshToken = new UserRefreshToken(userId, refreshToken.getToken());
            userRefreshTokenRepository.saveAndFlush(userRefreshToken);
        } else {
            // DB에 refresh 토큰 업데이트
            userRefreshToken.setRefreshToken(refreshToken.getToken());
        }


        int cookieMaxAge = (int) refreshTokenExpiry / 60;
        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
        CookieUtil.addCookie(response, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);


        return ResponseEntity.ok(accessToken);
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refreshToken (HttpServletRequest request, HttpServletResponse response) {


        // access token 확인
        String accessToken = HeaderUtil.getAccessToken(request);
        AuthToken authToken = tokenProvider.convertAuthToken(accessToken);
        if (!authToken.validate()) {
            return ResponseEntity.ok(new ResponseHeader(500, "accessToken이 올바르지 않습니다."));
        }

        // expired access token 인지 확인
        Claims claims = authToken.getExpiredTokenClaims();
        if (claims == null) {
            return ResponseEntity.ok(new ResponseHeader(500, "아직 accessToken이 만료되지 않았습니다."));
        }
        String userId = claims.getSubject();

        RoleType roleType = RoleType.of(claims.get("role", String.class));

        // refresh token
        String refreshToken = CookieUtil.getCookie(request, REFRESH_TOKEN)
                .map(Cookie::getValue)
                .orElse((null));
        AuthToken authRefreshToken = tokenProvider.convertAuthToken(refreshToken);

        if (authRefreshToken.validate()) {
            return ResponseEntity.ok(new ResponseHeader(500, "아직 refreshToken이 올바르지 않습니다."));
        }

        // userId refresh token 으로 DB 확인
        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserIdAndRefreshToken(userId, refreshToken);
        if (userRefreshToken == null) {
            return ResponseEntity.ok(new ResponseHeader(500, "아직 refreshToken이 올바르지 않습니다."));
        }

        Date now = new Date();
        AuthToken newAccessToken = tokenProvider.createAuthToken(
                userId,
                roleType.getCode(),
                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
        );

        long validTime = authRefreshToken.getTokenClaims().getExpiration().getTime() - now.getTime();

        // refresh 토큰 기간이 3일 이하로 남은 경우, refresh 토큰 갱신
        if (validTime <= THREE_DAYS_MSEC) {
            // refresh 토큰 설정
            long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

            authRefreshToken = tokenProvider.createAuthToken(
                    appProperties.getAuth().getTokenSecret(),
                    new Date(now.getTime() + refreshTokenExpiry)
            );

            // DB에 refresh 토큰 업데이트
            userRefreshToken.setRefreshToken(authRefreshToken.getToken());

            int cookieMaxAge = (int) refreshTokenExpiry / 60;
            CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
            CookieUtil.addCookie(response, REFRESH_TOKEN, authRefreshToken.getToken(), cookieMaxAge);
        }
        return ResponseEntity.ok(
                new AccessTokenResponse(
                        newAccessToken.getToken(),
                        new ResponseHeader(500, "아직 refreshToken이 올바르지 않습니다.")
                )
        );
    }



}
