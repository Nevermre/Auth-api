package br.com.e.authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ApplicationDto {
  private String appcode;
  private String appname;
}
