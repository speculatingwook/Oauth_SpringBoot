package com.speculatingwook.OauthSpringBoot.domain.login.controller;

import com.speculatingwook.OauthSpringBoot.domain.login.dto.request.DuplicateIdRequest;
import com.speculatingwook.OauthSpringBoot.domain.login.dto.request.SignupRequest;
import com.speculatingwook.OauthSpringBoot.domain.login.service.UserService;
import com.speculatingwook.OauthSpringBoot.global.common.dto.ResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    @PostMapping("/signUp")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<?> join(@Valid @RequestBody SignupRequest request) throws Exception {
        ResponseDto response = new ResponseDto(true, List.of(userService.signUp(request)));
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<?> getUser() {
        org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        ResponseDto response = new ResponseDto(true, List.of(userService.getUser(principal.getUsername())));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/duplicate-id")
    public ResponseEntity<?> checkDuplicateId(@RequestBody DuplicateIdRequest request) throws Exception {
        ResponseDto response = new ResponseDto(true, List.of(userService.checkDuplicateId(request)));
        return ResponseEntity.ok(response);
    }
}
