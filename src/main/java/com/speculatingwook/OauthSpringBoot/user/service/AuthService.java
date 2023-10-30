package com.speculatingwook.OauthSpringBoot.user.service;

import com.speculatingwook.OauthSpringBoot.global.config.properties.AppProperties;
import com.speculatingwook.OauthSpringBoot.global.dto.ResponseDto;
import com.speculatingwook.OauthSpringBoot.global.dto.ResponseHeader;
import com.speculatingwook.OauthSpringBoot.global.utils.CookieUtil;
import com.speculatingwook.OauthSpringBoot.global.utils.HeaderUtil;
import com.speculatingwook.OauthSpringBoot.user.dto.request.LoginRequest;
import com.speculatingwook.OauthSpringBoot.user.entity.user.UserRefreshToken;
import com.speculatingwook.OauthSpringBoot.user.oauth.entity.RoleType;
import com.speculatingwook.OauthSpringBoot.user.oauth.entity.UserPrincipal;
import com.speculatingwook.OauthSpringBoot.user.oauth.token.AuthToken;
import com.speculatingwook.OauthSpringBoot.user.oauth.token.AuthTokenProvider;
import com.speculatingwook.OauthSpringBoot.user.repository.UserRefreshTokenRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final AppProperties appProperties;
    private final AuthTokenProvider tokenProvider;
    private final UserRefreshTokenRepository userRefreshTokenRepository;

    private final static long THREE_DAYS_MSEC = 259200;
    private final static String REFRESH_TOKEN = "refresh_token";

    public ResponseEntity<?> login(HttpServletRequest request,
                                    HttpServletResponse response,
                                    LoginRequest loginRequest) {
        String userId = loginRequest.getUserId();
        String userPassword = loginRequest.getPassword();

        Authentication authentication = getAuthentication(userId, userPassword);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Date now = new Date();
        long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

        AuthToken accessToken = createToken(userId, authentication, now);
        AuthToken refreshToken = getRefreshToken(now, refreshTokenExpiry);

        checkRefreshToken(userId, refreshToken);
        executeCookie(request, response, refreshTokenExpiry, refreshToken);

        ResponseDto responseData = new ResponseDto(true, List.of(accessToken));
        return ResponseEntity.ok(responseData);
    }

    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        Date now = new Date();
        // access token 확인
        String accessToken = HeaderUtil.getAccessToken(request);
        AuthToken authToken = tokenProvider.convertAuthToken(accessToken);

        // expired access token 인지 확인
        Claims claims = authToken.getExpiredTokenClaims();

        if (claims == null) {
            return errorResponse("아직 accessToken이 만료되지 않았습니다.");
        }

        String userId = claims.getSubject();
        RoleType roleType = RoleType.of(claims.get("role", String.class));

        String refreshToken = CookieUtil.getCookie(request, REFRESH_TOKEN)
                .map(Cookie::getValue)
                .orElse((null));
        System.out.println("refreshtoken" + refreshToken);
        AuthToken authRefreshToken = tokenProvider.convertAuthToken(refreshToken);

        if (!authRefreshToken.validate()) {
            return errorResponse("refreshToken이 올바르지 않습니다.");
        }

        // userId refresh token 으로 DB 확인
        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserIdAndRefreshToken(userId, refreshToken);

        if (userRefreshToken == null) {
            System.out.println("2");
            return errorResponse("refreshToken이 올바르지 않습니다.");
        }

        long validTime = calculateValidTime(authRefreshToken);

        // refresh 토큰 기간이 3일 이하로 남은 경우, refresh 토큰 갱신
        if (validTime <= THREE_DAYS_MSEC) {
            long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();
            authRefreshToken = getRefreshToken(now, refreshTokenExpiry);
            userRefreshToken.setRefreshToken(authRefreshToken.getToken());

            executeCookie(request, response, refreshTokenExpiry, authRefreshToken);
        }

        return ResponseEntity.ok(new ResponseDto(true, List.of(createNewAccessToken(userId, roleType, now).getToken())));
    }


    private Authentication getAuthentication(String userId, String userPassword) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userId,
                        userPassword)
        );
    }

    private AuthToken createToken(String userId, Authentication authentication, Date currentTime) {
        return tokenProvider.createAuthToken(
                userId,
                ((UserPrincipal) authentication.getPrincipal()).getRoleType().getCode(),
                new Date(currentTime.getTime() + appProperties.getAuth().getTokenExpiry())
        );
    }

    private AuthToken getRefreshToken(Date currentTime, long refreshTokenExpiry) {
        return tokenProvider.createAuthToken(
                appProperties.getAuth().getTokenSecret(),
                new Date(currentTime.getTime() + refreshTokenExpiry)
        );
    }
    private AuthToken createNewAccessToken(String userId, RoleType roleType, Date currentTime) {
        return tokenProvider.createAuthToken(
                userId,
                roleType.getCode(),
                new Date(currentTime.getTime() + appProperties.getAuth().getTokenExpiry())
        );
    }

    private void checkRefreshToken(String userId, AuthToken refreshToken) {
        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserId(userId);
        if (userRefreshToken == null) {
            // 없는 경우 새로 등록
            userRefreshToken = new UserRefreshToken(userId, refreshToken.getToken());
            userRefreshTokenRepository.saveAndFlush(userRefreshToken);
        } else {
            // DB에 refresh 토큰 업데이트
            userRefreshToken.setRefreshToken(refreshToken.getToken());
        }
    }

    private void executeCookie(HttpServletRequest request,
                               HttpServletResponse response,
                               long refreshTokenExpiry,
                               AuthToken refreshToken) {
        int cookieMaxAge = (int) refreshTokenExpiry / 60;
        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
        CookieUtil.addCookie(response, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);
    }
    private long calculateValidTime(AuthToken authToken) {
        Date now = new Date();
        return authToken.getTokenClaims().getExpiration().getTime() - now.getTime();
    }
    private ResponseEntity<?> errorResponse(String message) {
        return ResponseEntity.ok(new ResponseHeader(500, message));
    }
}