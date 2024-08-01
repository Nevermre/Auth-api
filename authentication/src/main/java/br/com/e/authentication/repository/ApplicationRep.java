package br.com.e.authentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import br.com.e.authentication.model.Application;

@Repository
public interface ApplicationRep extends JpaRepository<Application, String> {

}
