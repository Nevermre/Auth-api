package br.com.e.authentication.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.e.authentication.model.Role;

@Repository
public interface RoleRep extends JpaRepository<Role, Long> {
  Optional<Role> findByRolename(String rolename);
}
