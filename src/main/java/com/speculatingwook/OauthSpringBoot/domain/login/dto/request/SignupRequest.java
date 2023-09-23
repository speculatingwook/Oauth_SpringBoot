package com.speculatingwook.OauthSpringBoot.domain.login.dto.request;

import com.speculatingwook.OauthSpringBoot.domain.login.oauth.entity.RoleType;
import lombok.*;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;


@Data
@AllArgsConstructor
@RequiredArgsConstructor
public class SignupRequest {

    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank(message = "이메일을 입력해주세요")
    private String email;

    @NotBlank(message = "아이디를 입력해주세요")
    private String userId;

    private RoleType role;

    @NotBlank(message = "비밀번호를 입력해주세요")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,30}$",
            message = "비밀번호는 8~30 자리이면서 1개 이상의 알파벳, 숫자, 특수문자를 포함해야합니다.")
    private String password;
}
