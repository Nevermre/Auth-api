package br.com.e.authentication.model;

import org.springframework.security.core.GrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@Entity
@Table(name = "roles")
@AllArgsConstructor
@NoArgsConstructor
public class Role implements GrantedAuthority {
  @Id
  @Column(nullable = false, unique = true)
  private String rolename;

  @Column(nullable = true)
  private String notes;

  @Override
  public String getAuthority() {
    return this.rolename;
  }

  public enum RolesEnum {
    ROLE_USER,
    ROLE_ADMIN
  }
}
