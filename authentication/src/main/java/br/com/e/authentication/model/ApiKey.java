package br.com.e.authentication.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.JoinColumn;

@Data
@Entity
@Table(name = "apikeys")
@AllArgsConstructor
@NoArgsConstructor
public class ApiKey {
  @Id
  @Column(nullable = false, unique = true)
  private String apikey;

  @Column(nullable = false)
  private String keyname;

  @Column(nullable = true)
  private String notes;

  @Column(nullable = false)
  private Boolean active;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(name = "apikey_applications", joinColumns = @JoinColumn(name = "apikey"), inverseJoinColumns = @JoinColumn(name = "appcode"))
  private List<Application> apps;
    
}
