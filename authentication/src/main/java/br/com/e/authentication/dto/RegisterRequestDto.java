package br.com.e.authentication.dto;

import lombok.Data;

@Data
public class RegisterRequestDto {
  private String name;
  private String username;
  private String email;
  private String password;
}
