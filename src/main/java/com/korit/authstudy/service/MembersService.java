package com.korit.authstudy.service;

import com.korit.authstudy.domain.entity.Member;
import com.korit.authstudy.dto.MemberRegisterDto;
import com.korit.authstudy.repository.MembersRepository;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MembersService {

    private final MembersRepository membersRepository;

    public void register(MemberRegisterDto dto) {
        System.out.println(dto);
        Member member = dto.toEntity();
        System.out.println(membersRepository.save(member));

    }


}




