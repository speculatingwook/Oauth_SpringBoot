package com.speculatingwook.OauthSpringBoot.domain.login.service;


import com.speculatingwook.OauthSpringBoot.domain.login.entity.user.User;
import com.speculatingwook.OauthSpringBoot.domain.login.repository.user.UserRepository;
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
