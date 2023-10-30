package com.speculatingwook.OauthSpringBoot.user.repository;

import com.speculatingwook.OauthSpringBoot.user.entity.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    User findByUserId(String userId);
    Boolean existsByUserId(String userId);
}
