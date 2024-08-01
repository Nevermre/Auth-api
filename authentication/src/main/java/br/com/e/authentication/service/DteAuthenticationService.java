package br.com.e.authentication.service;

import java.util.Base64;
import java.util.List;

import org.springframework.stereotype.Service;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.e.authentication.security.AuthModel;
import br.com.e.authentication.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

@Slf4j
@Service
public class DteAuthenticationService {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private DteTokenValidatorService dteTokenValidator;

    public Tuple2<String, String> login(String dteToken) throws JsonProcessingException, JsonMappingException {

        var mapper = new ObjectMapper();

        log.debug("login/data: {}", dteToken);
        byte[] decoded = Base64.getDecoder().decode(dteToken);
        String dteTokenStr = new String(decoded, StandardCharsets.UTF_8);

        log.debug("login/dteToken: {}", dteTokenStr);

        var dteTokenJson = mapper.readTree(dteTokenStr);
        var loggedIn = dteTokenJson.get("loggedIn").asBoolean();
        if (!loggedIn)
            throw new BadCredentialsException("User not logged in");

        var dteTokenValidatorResult = dteTokenValidator.validateToken(dteTokenJson);

        var isValidToken = dteTokenValidatorResult.getT1();
        var procuracao = dteTokenValidatorResult.getT2();

        if (!isValidToken)
            throw new BadCredentialsException("Invalid token");

        log.debug("login/validToken: {}", isValidToken);
        log.debug("login/procuracao: {}", procuracao);

        var username = dteTokenJson.get("usuario").get("cpfCnpj").asText();
        var dteTokenValue = dteTokenJson.get("token").asText();

        List<String> roleList = List.of("ROLE_USER", "ROLE_TAXPAYER");

        var name = username;

        try {

            name = dteTokenJson.get("usuario").get("nomeRazaoSocial").asText();
            log.debug("login/name: {}", name);

        } catch (Exception ex) {
            log.debug("Name not found");
        }

        String jwt = tokenProvider.generateToken(AuthModel.DTeAuthModel, username, roleList, dteTokenValue, procuracao,
                name);

        var res = Tuples.of(jwt, username);

        return res;
    }
}
