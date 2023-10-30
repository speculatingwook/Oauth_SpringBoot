package com.speculatingwook.OauthSpringBoot.user.service;


import com.speculatingwook.OauthSpringBoot.user.dto.request.DuplicateIdRequest;
import com.speculatingwook.OauthSpringBoot.user.dto.request.SignupRequest;
import com.speculatingwook.OauthSpringBoot.user.entity.user.User;
import com.speculatingwook.OauthSpringBoot.user.oauth.entity.ProviderType;
import com.speculatingwook.OauthSpringBoot.user.oauth.entity.RoleType;
import com.speculatingwook.OauthSpringBoot.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getUser() {
        org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByUserId(principal.getUsername());
    }

    public User signUp(SignupRequest request) throws Exception{
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new Exception("이미 존재하는 이메일입니다.");
        }
        if (userRepository.existsByUserId(request.getUserId())) {
            throw new Exception("중복되는 아이디입니다.");
        }

        User user = User.of(
                request.getUserId(),
                request.getUsername(),
                request.getEmail(),
                ProviderType.LOCAL,
                RoleType.USER,
                LocalDateTime.now(),
                LocalDateTime.now());
        user.encodePassword(request.getPassword());
        userRepository.save(user);
        return user;
    }
    public boolean checkDuplicateId(DuplicateIdRequest request) throws Exception {
        return userRepository.existsByUserId(request.getUserId());
    }
}