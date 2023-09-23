package com.speculatingwook.OauthSpringBoot.domain.login.service;


import com.speculatingwook.OauthSpringBoot.domain.login.dto.request.DuplicateIdRequest;
import com.speculatingwook.OauthSpringBoot.domain.login.dto.request.SignupRequest;
import com.speculatingwook.OauthSpringBoot.domain.login.entity.user.User;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.entity.ProviderType;
import com.speculatingwook.OauthSpringBoot.domain.login.oauth.entity.RoleType;
import com.speculatingwook.OauthSpringBoot.domain.login.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getUser(String userId) {
        return userRepository.findByUserId(userId);
    }
    @Transactional
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
