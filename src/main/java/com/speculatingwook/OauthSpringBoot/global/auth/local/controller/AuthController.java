package com.speculatingwook.OauthSpringBoot.global.auth.local.controller;

import com.speculatingwook.OauthSpringBoot.global.auth.local.dto.request.LoginRequest;
import com.speculatingwook.OauthSpringBoot.global.auth.local.dto.request.SignupRequest;
import com.speculatingwook.OauthSpringBoot.global.auth.local.dto.response.JwtResponse;
import com.speculatingwook.OauthSpringBoot.global.auth.local.model.ERole;
import com.speculatingwook.OauthSpringBoot.global.auth.local.model.Role;
import com.speculatingwook.OauthSpringBoot.global.auth.local.model.User;
import com.speculatingwook.OauthSpringBoot.global.auth.local.model.UserDetailsImpl;
import com.speculatingwook.OauthSpringBoot.global.auth.local.repository.RoleRepository;
import com.speculatingwook.OauthSpringBoot.global.auth.local.repository.UserRepository;
import com.speculatingwook.OauthSpringBoot.global.auth.local.security.jwt.JwtUtils;
import com.speculatingwook.OauthSpringBoot.global.common.dto.ResponseHeader;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthController {
    AuthenticationManager authenticationManager;
    JwtUtils jwtUtils;
    PasswordEncoder encoder;
    UserRepository userRepository;
    RoleRepository roleRepository;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new ResponseHeader(500, "Error: 유저 이름이 이미 있습니다!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new ResponseHeader(500, "Error: 존재하고 있는 이메일입니다!"));
        }

        // Create new user's account
        User user = User.of(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role이 존재하지 않습니다."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin" -> {
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role이 존재하지 않습니다."));
                        roles.add(adminRole);
                    }
                    case "mod" -> {
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role이 존재하지 않습니다."));
                        roles.add(modRole);
                    }
                    default -> {
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role이 존재하지 않습니다."));
                        roles.add(userRole);
                    }
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new ResponseHeader(200, "Success: 유저 등록 완료"));
    }


}
