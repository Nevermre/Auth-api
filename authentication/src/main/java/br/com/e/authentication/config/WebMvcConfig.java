package br.com.e.authentication.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
  private final long MAX_AGE_SECS = 3600;

  @Value("${app.cors.allowed-origins:*}")
  private String allowedOrigins;
  @Value("${app.cors.allowed-headers:*}")
  private String allowedHeaders;
  @Value("${app.cors.allowed-methods:*}")
  private String allowedMethods;
  
  @Override
  public void addCorsMappings(CorsRegistry registry) {
    var cors = new CorsConfiguration();
    cors.setAllowedOriginPatterns(getAllowedOrigins());
    cors.setAllowedHeaders(getAllowedHeaders());
    cors.setAllowedMethods(getAllowedMethods());
    registry.addMapping("/**")
        .combine(cors)
        .allowCredentials(false)
        .maxAge(MAX_AGE_SECS);
  }

  private List<String> getAllowedOrigins() {

    List<String> allowed = new ArrayList<String>();

    if (allowedOrigins != null && !allowedOrigins.isEmpty())
    {
      var splited = allowedOrigins.split(",");
      allowed = Arrays.asList(splited).stream().map(x -> x.trim()).toList();
    }
    
    return allowed;

  }

  private List<String> getAllowedMethods() {

    List<String> allowed = new ArrayList<String>();

    if (allowedMethods != null && !allowedMethods.isEmpty())
    {
      var splited = allowedMethods.split(",");
      allowed = Arrays.asList(splited).stream().map(x -> x.trim()).toList();
    }
    
    return allowed;

  }

  private List<String> getAllowedHeaders() {

    List<String> allowed = new ArrayList<String>();

    if (allowedHeaders != null && !allowedHeaders.isEmpty())
    {
      var splited = allowedHeaders.split(",");
      allowed = Arrays.asList(splited).stream().map(x -> x.trim()).toList();
    }
    
    return allowed;

  }
}
