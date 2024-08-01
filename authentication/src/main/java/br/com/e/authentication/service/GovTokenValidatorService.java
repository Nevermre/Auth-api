package br.com.e.authentication.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.json.internal.json_simple.parser.JSONParser;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;



@Service
@Slf4j
public class GovTokenValidatorService {

  @Value("${app.gov.jwt.validator.url:}")
  private String validatorUrl;

  @Value("${app.gov.jwt.validator.grant-type:}")
  private String govGrantType;

  @Value("${app.gov.jwt.validator.redirect-uri:}")
  private String govRedirectUri;

  @Value("${app.gov.jwt.validator.authorization:}")
  private String govAuthorization;

  public Tuple2<Boolean, String> validateToken(JsonNode jsonToken) {
    try {

      var mapper = new ObjectMapper();
      MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
      body.add("grant_type", govGrantType);
      body.add("code", jsonToken.get("code").asText());
      body.add("redirect_uri", govRedirectUri);

      var headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
      headers.set("Authorization", govAuthorization);

      log.debug("request Authorization: {}", govAuthorization);
      log.debug("request content: {}", body.toString());

      var request = new HttpEntity<>(body, headers);

      var rest = new RestTemplate();

      log.debug("request post {}", validatorUrl);
      var resp = rest.postForObject(validatorUrl, request, String.class);
      log.debug("request resp: {}", resp);

      var result = mapper.readTree(resp);

      var isValidToken = false;
      var govTokenStr = "";
      if (result.hasNonNull("access_token")) {
        isValidToken = true;
        log.debug("isValidToken: {}", isValidToken);
        log.debug("login/govToken: {}", result.get("access_token").asText());

        var splited = result.get("access_token").asText().split("\\.");
        var payload = splited[1];        
        byte[] decoded = Base64.getDecoder().decode(payload);
        govTokenStr = new String(decoded, StandardCharsets.UTF_8);

      }

      var tuple = Tuples.of(isValidToken, govTokenStr);
      log.debug("tuple: {}", tuple);

      return tuple;

    } catch (Exception e) {

      log.error("validation token error: {}", e.getMessage());

      return Tuples.of(false, "");
    }
  }
  
}




