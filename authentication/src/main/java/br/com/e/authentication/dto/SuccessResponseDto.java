package br.com.e.authentication.dto;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SuccessResponseDto implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String version = "v1";
  private Boolean success;
}
