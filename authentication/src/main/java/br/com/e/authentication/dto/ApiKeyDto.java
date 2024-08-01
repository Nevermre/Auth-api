package br.com.e.authentication.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ApiKeyDto {
  private String keyName;
  private String notes;
  private Boolean active;
  private List<ApplicationDto> apps;
}
