package br.com.e.authentication.service;

import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.e.authentication.error.custom.NotFound;
import br.com.e.authentication.model.Role;
import br.com.e.authentication.repository.UserRep;
import br.com.e.authentication.security.AuthModel;
import br.com.e.authentication.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

@Slf4j
@Service
public class GovAuthenticationService {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private GovTokenValidatorService govTokenValidator;

    @Autowired
    private UserDetailsService customUserDetailsService;

    @Autowired
    private UserRep userRepository;

    public Tuple2<String, String> login(String govToken) throws JsonProcessingException, JsonMappingException {

        var mapper = new ObjectMapper();

        log.debug("login/data: {}", govToken);
        byte[] decoded = Base64.getDecoder().decode(govToken);
        String govTokenStr = new String(decoded, StandardCharsets.UTF_8);

        log.debug("login/govToken: {}", govTokenStr);

        var govTokenJson = mapper.readTree(govTokenStr);
        
        //appCode for authentication
        var appCode = govTokenJson.get("appCode").asText();

        var govTokenValidatorResult = govTokenValidator.validateToken(govTokenJson);

        var isValidToken = govTokenValidatorResult.getT1();
        var tokenString = govTokenValidatorResult.getT2();

        if (!isValidToken)
            throw new BadCredentialsException("Invalid token");

        log.debug("login/gov/validToken: {}", isValidToken);
        log.debug("login/gov/token: {}", tokenString);

        var tokenObject = mapper.readTree(tokenString);

        var username = tokenObject.get("cpf").asText();
        var cpfCnpj = tokenObject.get("cpf").asText();

        // List<String> roleList = List.of("ROLE_USER", "ROLE_TAXPAYER");

        var user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new NotFound("User not found."));

        var apps = user.getApps();

        var appaccess = apps.stream().filter(x -> x.getAppcode().equals(appCode))
                .collect(Collectors.toList());

        if (appaccess.size() == 0)
            throw new NotFound("User has not access to the application");

        var roleList = user.getRoles().stream().map(role -> role.getRolename().toString()).toList();

        var name = "";

        try {

            name = tokenObject.get("name").asText();
            log.debug("login/name: {}", name);

        } catch (Exception ex) {
            log.debug("Name not found");
        }

        String jwt = tokenProvider.generateToken(AuthModel.DTeAuthModel, username, roleList, tokenString, cpfCnpj,
                name);

        var res = Tuples.of(jwt, username);

        return res;
    }
}
