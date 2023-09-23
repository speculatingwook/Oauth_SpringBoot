package com.speculatingwook.OauthSpringBoot.domain.login.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@AllArgsConstructor
@RequiredArgsConstructor
public class DuplicateIdRequest {
    private String userId;
}
