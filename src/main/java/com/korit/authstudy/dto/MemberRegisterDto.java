package com.korit.authstudy.dto;

import com.korit.authstudy.domain.entity.Member;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Data
public class MemberRegisterDto extends Object {
    private String username;
    private String password;
    private String fullName;
    private String email;

//    public Member toEntity() {
//        Member member = new Member();
//        member.setMemberName(username);
//        member.setPassword(password);
//        member.setName(fullName);
//        member.setEmail(email);
//        return member;
//    }

    public Member toEntity() {
        return Member.builder()
                .memberName(username)
                .password(password)
                .name(fullName)
                .email(email)
                .build();
    }
}









