package br.com.e.authentication.service;

import java.util.ArrayList;
import java.util.Base64;

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
public class AstraAuthenticationService {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private AstraTokenValidatorService astraTokenValidator;

    public Tuple2<String, String> login(String astraToken) throws JsonProcessingException, JsonMappingException {

        var mapper = new ObjectMapper();

        var splited = astraToken.split("\\.");

        var payload = splited[1];

        log.debug("login/astraToken: {}", astraToken);
        byte[] decoded = Base64.getDecoder().decode(payload);
        String astraTokenStr = new String(decoded, StandardCharsets.UTF_8);

        log.debug("login/astraToken: {}", astraTokenStr);

        var astraTokenJson = mapper.readTree(astraTokenStr);

        var astraTokenValidatorResult = astraTokenValidator.validateToken(astraToken);

        log.debug("login/validToken: {}", astraTokenValidatorResult);

        if (!astraTokenValidatorResult)
            throw new BadCredentialsException("Invalid token");

        var username = astraTokenJson.get("matricula").asText();
        log.debug("login/username: {}", username);

        var roleList = new ArrayList<String>();
        roleList.add("ROLE_USER");

        var name = username;

        try {
            var fds = astraTokenJson.fields();
            while (fds.hasNext()) {
                var f = fds.next();
                var key = f.getKey();
                var value = f.getValue();
                if (key.contains(":") && value.isBoolean() && value.asBoolean()) {
                    roleList.add(key);
                }
            }
            log.debug("login/roles: {}", roleList);

        } catch (Exception ex) {
            log.debug("Name not found");
        }

        String jwt = tokenProvider.generateToken(AuthModel.AstraAuthModel, username, roleList, astraToken, username, name);

        var res = Tuples.of(jwt, username);

        return res;
    }

    public String refresh(String jwt, String system)
            throws JsonProcessingException, JsonMappingException {

        log.debug("[refresh] system: {}, jwt: {} ", system, jwt);

        jwt = jwt.replace("Bearer ", "");

        var astraToken = tokenProvider.getEmbeddedToken(jwt);

        log.debug("login/astraToken: {}", astraToken);

        var newToken = astraTokenValidator.refreshToken(astraToken, system);

        if (newToken == null || newToken.isEmpty())
            throw new BadCredentialsException("Invalid token");
        
        return newToken;
    }
}
