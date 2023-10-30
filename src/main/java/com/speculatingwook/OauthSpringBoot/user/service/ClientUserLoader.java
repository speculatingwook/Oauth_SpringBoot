package com.speculatingwook.OauthSpringBoot.user.service;

import com.speculatingwook.OauthSpringBoot.user.entity.user.User;
import com.speculatingwook.OauthSpringBoot.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ClientUserLoader {
    private final UserRepository userRepository;
    public User getClientUser() {
        org.springframework.security.core.userdetails.User principal =
                (org.springframework.security.core.userdetails.User)
                        SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userRepository.findByUserId(principal.getUsername());
    }
}