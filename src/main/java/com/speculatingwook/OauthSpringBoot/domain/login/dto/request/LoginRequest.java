package com.speculatingwook.OauthSpringBoot.domain.login.dto.request;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Data
@Getter
@NoArgsConstructor
public class LoginRequest {
    private String userId;
    private String password;
}
