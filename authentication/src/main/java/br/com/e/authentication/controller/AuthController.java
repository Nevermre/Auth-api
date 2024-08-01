package br.com.e.authentication.controller;

import java.net.URI;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import br.com.e.authentication.dto.ApiKeyDto;
import br.com.e.authentication.dto.DataResponseDto;
import br.com.e.authentication.dto.JwtAuthenticationDto;
import br.com.e.authentication.dto.LoginRequestDto;
import br.com.e.authentication.dto.RegisterRequestDto;
import br.com.e.authentication.model.ApiKey;
import br.com.e.authentication.model.Role;
import br.com.e.authentication.model.User;
import br.com.e.authentication.service.AuthenticationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@CrossOrigin(origins = "*")
@Tag(name = "Auth", description = "Auth endpoints")
@RequestMapping("/api/v1/auth")
public class AuthController {

  @Autowired
  private AuthenticationService authenticationService;

  @PostMapping("/login/username")
  public ResponseEntity<DataResponseDto<JwtAuthenticationDto>> usernameLogin(
      @RequestBody LoginRequestDto loginRequest) {

    log.debug("[usernameLogin] UsernameOrEmail: {}", loginRequest.getUsernameOrEmail());

    var jwt = authenticationService.usernameLogin(loginRequest);

    return ResponseEntity.status(HttpStatus.OK)
        .body(new DataResponseDto<JwtAuthenticationDto>(new JwtAuthenticationDto(jwt)));
  }

  @PostMapping("/login/register")
  public ResponseEntity<?> registerUser(@RequestBody RegisterRequestDto registerRequest) {

    log.debug("[registerUser] Username: {}", registerRequest.getUsername());

    var user = authenticationService.registerUser(registerRequest);

    URI location = ServletUriComponentsBuilder
        .fromCurrentContextPath().path("/users/{username}")
        .buildAndExpand(user.getUsername()).toUri();

    return ResponseEntity.created(location).body(new DataResponseDto<String>("User registered successfully"));
  }

  @GetMapping("/login/dte")
  public ResponseEntity<DataResponseDto<?>> dteLogin(String data) {

    log.debug("[dteLogin] received DTe token: {}", data);

    try {

      var jwt = authenticationService.dteLogin(data);

      return ResponseEntity.status(HttpStatus.OK)
          .body(new DataResponseDto<JwtAuthenticationDto>(new JwtAuthenticationDto(jwt)));

    } catch (JsonMappingException e) {
      log.error(e.getMessage());

      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new DataResponseDto<String>("Invalid token"));
    } catch (JsonProcessingException e) {
      log.error(e.getMessage());

      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new DataResponseDto<String>("Invalid token"));
    }
  }

  @GetMapping("/login/gov")
  public ResponseEntity<DataResponseDto<?>> govLogin(String data) {

    log.debug("[govLogin] received Gov token: {}", data);

    try {

      var jwt = authenticationService.govLogin(data);

      return ResponseEntity.status(HttpStatus.OK)
          .body(new DataResponseDto<JwtAuthenticationDto>(new JwtAuthenticationDto(jwt)));

    } catch (JsonMappingException e) {
      log.error(e.getMessage());

      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new DataResponseDto<String>("Invalid token"));
    } catch (JsonProcessingException e) {
      log.error(e.getMessage());

      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new DataResponseDto<String>("Invalid token"));
    }
  }

  @GetMapping("/isauthenticated")
  public ResponseEntity<DataResponseDto<ObjectNode>> isAuthenticated() {

    log.debug("[isAuthenticated] Checking if is authenticated");

    var mapper = new ObjectMapper();

    var ret = mapper.createObjectNode();
    var principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    var roles = new StringBuilder();

    List<Role> roleList = SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().map(x -> (Role)x).toList();

    for (Role role : roleList) {
      roles.append(role.getAuthority() + ",");
    }
        
    if (roles.length() > 0)
      roles.deleteCharAt(roles.length() - 1);

    ret.put("isValid", SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
    var id = principal.getName();
    var authModel = "UsernameAuthModel";
    var authObject = "";
    if (principal.getName().contains(":")) {
      authModel = principal.getName().split(":")[0];
      id = principal.getName().split(":")[1];
      authObject = principal.getName().split(":")[2];
    }
    
    ret.put("id", id);
    ret.put("authModel", authModel);
    ret.put("roles", roles.toString());
    ret.put("authObject", authObject);

    log.debug("[isAuthenticated] returning ", ret);

    return ResponseEntity.status(HttpStatus.OK)
        .body(new DataResponseDto<ObjectNode>(ret));
  }

  @GetMapping("/login/astra")
  public ResponseEntity<DataResponseDto<?>> tokenAstraIsValid(@RequestHeader("Authorization") String astraToken) {

    log.debug("Enter in tokenAstraIsValid {}", astraToken);

    String jwt = null;
    try {

      jwt = authenticationService.astraLogin(astraToken);

    } catch (JsonProcessingException e) {

      log.error(e.getMessage());

      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new DataResponseDto<String>("Invalid token"));
    }

    return ResponseEntity.status(HttpStatus.OK)
        .body(new DataResponseDto<JwtAuthenticationDto>(new JwtAuthenticationDto(jwt)));
  }

  @GetMapping("/token/astra/refresh/{system}")
  public ResponseEntity<DataResponseDto<?>> refresh(@PathVariable("system") String system,
      @RequestHeader("Authorization") String bearerToken) {

    log.debug("Enter in refresh token: {}", bearerToken);

    String jwt = "";
    try {

      jwt = authenticationService.getAstraRefreshToken(bearerToken, system);

    } catch (JsonProcessingException e) {

      log.error(e.getMessage());

      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new DataResponseDto<String>("Invalid token"));
    }

    return ResponseEntity.status(HttpStatus.OK)
        .body(new DataResponseDto<JwtAuthenticationDto>(new JwtAuthenticationDto(jwt)));
  }

  @PostMapping("/apikey/register")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  public ResponseEntity<?> apiKeyRegister(@RequestBody ApiKeyDto registerRequest) {

    log.debug("[apiKeyRegister] ApiKey register request: {}", registerRequest);

    var apiKey = authenticationService.apiKeyRegister(registerRequest);

    URI location = ServletUriComponentsBuilder
        .fromCurrentContextPath().path("/apikey/{apikey}")
        .buildAndExpand(apiKey.getApikey()).toUri();

    return ResponseEntity.created(location).body(new DataResponseDto<ApiKey>(apiKey));
  }

  @GetMapping("/apikey/{apikey}")
  public ResponseEntity<DataResponseDto<?>> getApiKey(@PathVariable("apikey") String apikey) {

    log.debug("[getApiKey] ApiKey {}", apikey);

    var apiKeyObj = authenticationService.getApiKey(apikey);

    return ResponseEntity.status(HttpStatus.OK)
      .body(new DataResponseDto<ApiKeyDto>(apiKeyObj));
  }

}
