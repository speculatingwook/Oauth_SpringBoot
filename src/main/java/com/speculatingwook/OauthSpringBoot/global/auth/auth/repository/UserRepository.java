package com.speculatingwook.OauthSpringBoot.global.auth.auth.repository;

import com.speculatingwook.OauthSpringBoot.global.auth.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
