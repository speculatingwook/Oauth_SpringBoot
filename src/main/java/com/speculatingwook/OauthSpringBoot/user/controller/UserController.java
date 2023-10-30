package com.speculatingwook.OauthSpringBoot.user.controller;

import com.speculatingwook.OauthSpringBoot.global.dto.ResponseDto;
import com.speculatingwook.OauthSpringBoot.user.dto.request.DuplicateIdRequest;
import com.speculatingwook.OauthSpringBoot.user.dto.request.SignupRequest;
import com.speculatingwook.OauthSpringBoot.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<?> join(@Valid @RequestBody SignupRequest request) throws Exception {
        ResponseDto response = new ResponseDto(true, List.of(userService.signUp(request)));
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<?> getUser() {
        ResponseDto response = new ResponseDto(true, List.of(userService.getUser()));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/duplicate-id")
    public ResponseEntity<?> checkDuplicateId(@RequestBody DuplicateIdRequest request) throws Exception {
        ResponseDto response = new ResponseDto(true, List.of(userService.checkDuplicateId(request)));
        return ResponseEntity.ok(response);
    }
}
