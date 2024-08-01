package br.com.e.authentication.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
  private String appcode;
  private String usernameOrEmail;
  private String password;  
}
