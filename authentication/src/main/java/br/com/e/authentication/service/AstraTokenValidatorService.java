package br.com.e.authentication.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AstraTokenValidatorService {

  @Value("${app.auth_astra.url:}")
  private String authAstraUrl;

  public Boolean validateToken(String astraToken) {

    try {

      var headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.set("Authorization", astraToken);

      log.debug("request Authorization: {}", astraToken);

      var request = new HttpEntity<String>(null, headers);

      var rest = new RestTemplate();
      
      var url = authAstraUrl + "/api/v1/auth/astra/token";

      log.debug("request get {}", url);
      
      var resp = rest.exchange(url, HttpMethod.GET, request, String.class);

      log.debug("request resp: {}", resp.getBody());

      if (resp.getBody().equals("true"))
        return true;

    } catch (Exception e) {

      log.error("validation token error: {}", e.getMessage());
      
    }

    return false;

  }

  public String refreshToken(String astraToken, String system) {
    
    var jwt = "";

    try {

      var mapper = new ObjectMapper();
      var headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.set("Authorization", astraToken);

      log.debug("request Authorization: {}", astraToken);

      var request = new HttpEntity<String>(null, headers);

      var rest = new RestTemplate();
      
      var url = authAstraUrl + "/api/v1/auth/astra/token/refresh/" + system;

      log.debug("request get {}", url);
      
      var resp = rest.exchange(url, HttpMethod.GET, request, String.class);

      log.debug("request resp: {}", resp.getBody());

      var result = mapper.readTree(resp.getBody());

      jwt = result.get("token").asText().replaceAll("Bearer ", "");

    } catch (Exception e) {

      log.error("validation token error: {}", e.getMessage());
      
    }

    return jwt;

  }

}