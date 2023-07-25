package com.speculatingwook.OauthSpringBoot.domain.login.auth.service;


import com.speculatingwook.OauthSpringBoot.domain.login.auth.entity.User;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getUser(String userId) {
        return userRepository.findByUserId(userId);
    }
}
