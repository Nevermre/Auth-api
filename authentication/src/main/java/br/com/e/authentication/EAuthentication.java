package br.com.e.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@EnableCaching
@SpringBootApplication
public class EAuthentication {

	public static void main(String[] args) {
		SpringApplication.run(EAuthentication.class, args);
	}
}