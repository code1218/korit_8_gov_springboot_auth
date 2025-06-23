package com.korit.authstudy.dto;

import lombok.Data;

@Data
public class UserPasswordModifyDto {
    private String oldPassword;
    private String newPassword;
    private String newPasswordCheck;
}
