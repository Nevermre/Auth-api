package br.com.e.authentication.service;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

@Service
@Slf4j
public class DteTokenValidatorService {

  @Value("${app.dte.jwt.validator.url:}")
  private String validatorUrl;

  @Value("${app.dte.auth.url:}")
  private String dteAuthUrl;

  @Value("${app.dte.auth.code:}")
  private String authCode;

  @Value("${app.dte.auth.pass:}")
  private String authPass;

  public Tuple2<Boolean, String> validateToken(JsonNode jsonJwt) {
    try {
      var dteApiToken = getDteApiToken();

      var mapper = new ObjectMapper();
      var body = mapper.createObjectNode();
      body.put("codUsuario", jsonJwt.get("usuario").get("codigo").asLong());
      body.put("nomeRazaoSocial", jsonJwt.get("usuario").get("nomeRazaoSocial").asText());
      body.put("cpfCnpj", jsonJwt.get("usuario").get("cpfCnpj").asText());
      body.put("email", jsonJwt.get("usuario").get("email").asText());
      body.put("token", jsonJwt.get("token").asText());

      var headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.set("Authorization", dteApiToken);

      var content = mapper.writeValueAsString(body);
      log.debug("request Authorization: {}", dteApiToken);
      log.debug("request content: {}", content);

      var request = new HttpEntity<String>(content, headers);

      var rest = new RestTemplate();

      log.debug("request post {}", validatorUrl);
      var resp = rest.postForObject(validatorUrl, request, String.class);
      log.debug("request resp: {}", resp);

      var result = mapper.readTree(resp);

      var isValidToken = false;
      var cpfCnpj = "";
      if (result.hasNonNull("resultado")) {
        isValidToken = result.get("resultado").get("token").asBoolean();
        log.debug("isValidToken: {}", isValidToken);

        if (result.get("resultado").hasNonNull("procuracao")) {
          if (result.get("resultado").get("procuracao").hasNonNull("outorgante")) {
            log.debug("has outorgante");
            cpfCnpj = result.get("resultado").get("procuracao").get("outorgante").get("cpfCnpj").asText();
          } else
            log.debug("hasnt outorgante");
        } else {
          log.debug("hasnt procuracao ");
          cpfCnpj = result.get("resultado").get("cpfCnpj").asText();
        }
      }

      var tuple = Tuples.of(isValidToken, cpfCnpj);
      log.debug("tuple: {}", tuple);

      return tuple;

    } catch (Exception e) {

      log.error("validation token error: {}", e.getMessage());

      return Tuples.of(false, "");
    }
  }

  private String getDteApiToken() throws JsonMappingException, JsonProcessingException {
    var mapper = new ObjectMapper();

    var rest = new RestTemplate();

    var uriVariables = new HashMap<String, String>();
    uriVariables.put("codigo", authCode);
    uriVariables.put("senha", authPass);

    var url = dteAuthUrl + "?codigo={codigo}&senha={senha}";

    log.debug("request post {}", url);
    log.debug("uri variables {}", uriVariables);

    var resp = rest.postForObject(url, null, String.class, uriVariables);

    log.debug("request resp: {}", resp);

    var result = mapper.readTree(resp);

    return result.get("resultado").asText();
  }
}
