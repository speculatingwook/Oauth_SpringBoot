package com.speculatingwook.OauthSpringBoot.global.auth.local.repository;

import com.speculatingwook.OauthSpringBoot.global.auth.local.model.ERole;
import com.speculatingwook.OauthSpringBoot.global.auth.local.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
