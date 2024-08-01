package br.com.e.authentication.config;

import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@Configuration
@OpenAPIDefinition(info = @Info(title = "API auth", version = "v1"))
@SecurityScheme(name = "Bearer", type = SecuritySchemeType.HTTP, scheme = "bearer")
public class SwaggerConfig {

}