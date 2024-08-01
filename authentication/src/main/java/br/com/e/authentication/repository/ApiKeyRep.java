package br.com.e.authentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.e.authentication.model.ApiKey;

import java.util.Optional;

@Repository
public interface ApiKeyRep extends JpaRepository<ApiKey, String> {
  Optional<ApiKey> findByApikey(String apikey);

}
