package com.speculatingwook.OauthSpringBoot.user.entity.user;


import com.fasterxml.jackson.annotation.JsonBackReference;
import com.speculatingwook.OauthSpringBoot.user.oauth.entity.ProviderType;
import com.speculatingwook.OauthSpringBoot.user.oauth.entity.RoleType;
import lombok.*;
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Size(max = 64)
    private String userId;

    @NotBlank
    @Size(max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(max = 120)
    private String password;

    @Nullable
    @Size(max = 512)
    private String profileImageUrl;

    @Enumerated(EnumType.STRING)
    @NotNull
    private ProviderType providerType;

    @Enumerated(EnumType.STRING)
    @NotNull
    private RoleType roleType;

    @NotNull
    private LocalDateTime createdAt;

    @NotNull
    private LocalDateTime modifiedAt;

    private User(String userId,
                 String username,
                 String email,
                 String profileImageUrl,
                 ProviderType providerType,
                 RoleType roleType,
                 LocalDateTime createdAt,
                 LocalDateTime modifiedAt) {
        this.userId = userId;
        this.username = username;
        this.password = "NO_PASS";
        this.email = email != null ? email : "NO_EMAIL";
        this.profileImageUrl = profileImageUrl != null ? profileImageUrl : "";
        this.providerType = providerType;
        this.roleType = roleType;
        this.createdAt = createdAt;
        this.modifiedAt = modifiedAt;
    }
    private User(String userId,
                 String username,
                 String email,
                 ProviderType providerType,
                 RoleType roleType,
                 LocalDateTime createdAt,
                 LocalDateTime modifiedAt) {
        this.userId = userId;
        this.username = username;
        this.password = "NO_PASS";
        this.email = email != null ? email : "NO_EMAIL";
        this.profileImageUrl = "";
        this.providerType = providerType;
        this.roleType = roleType;
        this.createdAt = createdAt;
        this.modifiedAt = modifiedAt;
    }

    public static User of(String userId,
                          String username,
                          String email,
                          String profileImageUrl,
                          ProviderType providerType,
                          RoleType roleType,
                          LocalDateTime createdAt,
                          LocalDateTime modifiedAt) {
        return new User(userId,username,  email, profileImageUrl, providerType, roleType, createdAt, modifiedAt );
    }
    public static User of(String userId,
                          String username,
                          String email,
                          ProviderType providerType,
                          RoleType roleType,
                          LocalDateTime createdAt,
                          LocalDateTime modifiedAt) {
        return new User(userId,username,  email, providerType, roleType, createdAt, modifiedAt);
    }
    public void setUsername(String name) {
        this.username = name;
    }

    public void setProfileImageUrl(String imageUrl) {
        this.profileImageUrl = imageUrl;
    }

    public void encodePassword(String rawPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        this.password = passwordEncoder.encode(rawPassword);
    }
}