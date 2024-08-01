package br.com.e.authentication.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@Entity
@Table(name = "applications")
@AllArgsConstructor
@NoArgsConstructor
public class Application {
  @Id
  @Column(nullable = false, unique = true)
  private String appcode;
  @Column(nullable = false)
  private String appname;

}
