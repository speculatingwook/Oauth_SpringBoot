package com.speculatingwook.OauthSpringBoot.domain.login.auth.dto.response;

import com.speculatingwook.OauthSpringBoot.global.common.dto.ResponseHeader;

public class AccessTokenResponse {
    private String token;
    ResponseHeader header;

    public AccessTokenResponse(String token, ResponseHeader header) {
        this.token = token;
        this.header = header;
    }
}
