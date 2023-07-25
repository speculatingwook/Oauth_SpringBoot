package com.speculatingwook.OauthSpringBoot.domain.login.auth.service;

import com.speculatingwook.OauthSpringBoot.domain.login.auth.entity.User;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.entity.UserPrincipal;
import com.speculatingwook.OauthSpringBoot.domain.login.auth.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserId(username);
        if (user == null) {
            throw new UsernameNotFoundException("Can not find username.");
        }
        return UserPrincipal.create(user);
    }
}
