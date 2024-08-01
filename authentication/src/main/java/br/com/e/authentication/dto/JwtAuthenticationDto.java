package br.com.e.authentication.dto;

import lombok.Data;

@Data
public class JwtAuthenticationDto {
  public static String INVALID_USER_OR_PWD = "INVALID_USER_OR_PWD";

  private String accessToken;
  private String tokenType = "Bearer";

  public JwtAuthenticationDto(String accessToken) {
    this.accessToken = accessToken;
  }
}
