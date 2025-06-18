package com.korit.authstudy.controller;

import com.korit.authstudy.dto.MemberRegisterDto;
import com.korit.authstudy.service.MembersService;
import com.korit.authstudy.service.UsersService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MembersController {

    private final MembersService membersService;

    @PostMapping("/api/members")
    public ResponseEntity<?> register(@RequestBody MemberRegisterDto dto) {
        // getClass().getName() + "@" + Integer.toHexString(hashCode());
        // com.korit.authstudy.dto.MemberRegisterDto + @ + 72dc7ee9
        membersService.register(dto);
        return ResponseEntity.ok(null);
    }

    @GetMapping("/api/members")
    public ResponseEntity<?> getUser() {
        return ResponseEntity.ok(null);
    }
}











