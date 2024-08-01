package br.com.e.authentication.service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import br.com.e.authentication.dto.ApiKeyDto;
import br.com.e.authentication.dto.ApplicationDto;
import br.com.e.authentication.dto.LoginRequestDto;
import br.com.e.authentication.dto.RegisterRequestDto;
import br.com.e.authentication.error.custom.BadRequest;
import br.com.e.authentication.error.custom.NotFound;
import br.com.e.authentication.model.ApiKey;
import br.com.e.authentication.model.Application;
import br.com.e.authentication.model.Role;
import br.com.e.authentication.model.User;
import br.com.e.authentication.model.Role.RolesEnum;
import br.com.e.authentication.repository.ApiKeyRep;
import br.com.e.authentication.repository.ApplicationRep;
import br.com.e.authentication.repository.RoleRep;
import br.com.e.authentication.repository.UserRep;
import br.com.e.authentication.security.AuthModel;
import br.com.e.authentication.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AuthenticationService {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRep userRepository;
    @Autowired
    private JwtTokenProvider tokenProvider;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private DteAuthenticationService dteAuthenticationService;
    @Autowired
    private AstraAuthenticationService astraAuthenticationService;
    @Autowired
    private GovAuthenticationService govAuthenticationService;
    @Autowired
    private UserDetailsService customUserDetailsService;
    @Autowired
    private RoleRep roleRepository;
    @Autowired
    private ApiKeyRep apiKeyRep;
    @Autowired
    private ApplicationRep appRep;

    public String usernameLogin(LoginRequestDto loginRequest) {

        String usernameOrEmail = loginRequest.getUsernameOrEmail();

        var user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> new NotFound("User not found."));

        var apps = user.getApps();

        var appaccess = apps.stream().filter( x -> x.getAppcode().equals(loginRequest.getAppcode()))
            .collect( Collectors.toList());
        
        if (appaccess.size() == 0)
            throw new NotFound("User has not access to the application");

        var flaggedUsername = AuthModel.UsernameAuthModel.GetModel() + ":" + usernameOrEmail;

        var userToken = new UsernamePasswordAuthenticationToken(flaggedUsername, loginRequest.getPassword());

        var authentication = authenticationManager.authenticate(userToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        var roleList = user.getRoles().stream().map(role -> role.getRolename().toString()).toList();
        //roleList.addAll(apps.stream().map(x -> "ROLE_APP_" + x.getAppcode()).toList());

        var authObject = "-1"; // can read all
        var embeddedToken = "";

        var jwt = tokenProvider.generateToken(AuthModel.UsernameAuthModel, usernameOrEmail, roleList, embeddedToken,
                authObject, null);

        log.debug("[usernameLogin] User {} logged in with success", usernameOrEmail);

        return jwt;
    }

    public User registerUser(RegisterRequestDto registerRequest) {

        var res = userRepository.findByUsername(registerRequest.getUsername());
        if (!res.isEmpty())
            throw new BadRequest("Username is already taken!");

        res = userRepository.findByEmail(registerRequest.getEmail());
        if (!res.isEmpty())
            throw new BadRequest("Email Address already in use!");

        User user = new User(registerRequest.getName(), registerRequest.getUsername(),
                registerRequest.getEmail(), registerRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        Role userRole = roleRepository.findByRolename(RolesEnum.ROLE_USER.name())
                .orElseThrow(() -> new InternalError("User Role not set."));

        user.setRoles(List.of(userRole));

        user = userRepository.save(user);

        log.debug("[registerUser] user {} registered with success: {} ", registerRequest.getUsername());

        return user;
    }

    public String dteLogin(String dteToken) throws JsonMappingException, JsonProcessingException {
        
        var res = dteAuthenticationService.login(dteToken);

        var jwt = res.getT1();

        var username = res.getT2();

        var flaggedUsername = AuthModel.DTeAuthModel.GetModel() + ":" + username;

        var userToken = new UsernamePasswordAuthenticationToken(flaggedUsername, username);

        var authentication = authenticationManager.authenticate(userToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("[dteLogin] User {} logged in with success", username);

        return jwt;
    }

    public String govLogin(String dteToken) throws JsonMappingException, JsonProcessingException {
        
        var res = govAuthenticationService.login(dteToken);

        var jwt = res.getT1();

        var username = res.getT2();

        var flaggedUsername = AuthModel.GovBrAuthModel.GetModel() + ":" + username;

        var userToken = new UsernamePasswordAuthenticationToken(flaggedUsername, username);

        var authentication = authenticationManager.authenticate(userToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("[dteLogin] User {} logged in with success", username);

        return jwt;
    }

    public String astraLogin(String astraToken) throws JsonMappingException, JsonProcessingException {

        var res = astraAuthenticationService.login(astraToken);

        var jwt = res.getT1();

        var username = res.getT2();

        var flaggedUsername = AuthModel.AstraAuthModel.GetModel() + ":" + username;

        var userToken = new UsernamePasswordAuthenticationToken(flaggedUsername, username);

        var authentication = authenticationManager.authenticate(userToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.debug("[astraLogin] User {} logged in with success", username);

        return jwt;
    }

    public String getAstraRefreshToken(String astraToken, String system)
            throws JsonMappingException, JsonProcessingException {

        var refreshedToken = astraAuthenticationService.refresh(astraToken, system);

        log.debug("[getAstraRefreshToken] Refreshed token: {}", refreshedToken);

        return refreshedToken;
    }

    public ApiKey apiKeyRegister(ApiKeyDto registerRequest) {

        if (registerRequest == null
                || registerRequest.getApps() == null
                || registerRequest.getApps().size() == 0)
            throw new BadRequest("Invalid ApiKey.");

        var appIds = registerRequest.getApps().stream().map(x -> x.getAppcode())
                .collect(Collectors.toList());

        var apps = appRep.findAllById(appIds);

        var uuid = UUID.randomUUID();

        var apiKey = new ApiKey(
                uuid.toString(), registerRequest.getKeyName(),
                registerRequest.getNotes(), registerRequest.getActive(),
                apps);

        apiKey = apiKeyRep.save(apiKey);

        log.debug("[apiKeyRegister] apiKey registered with success: {} ", apiKey);

        return apiKey;
    }

    public ApiKeyDto getApiKey(String apiKey) {

        if (!StringUtils.hasText(apiKey))
            throw new BadRequest("Invalid ApiKey.");

        var apiKeyObj = apiKeyRep.getReferenceById(apiKey);

        var apps = apiKeyObj.getApps().stream().map(x -> new ApplicationDto(x.getAppcode(), x.getAppname()))
                .collect(Collectors.toList());

        var apiKeyDto = new ApiKeyDto(apiKeyObj.getKeyname(),
                apiKeyObj.getNotes(),
                apiKeyObj.getActive(),
                apps);

        log.debug("[apiKeyRegister] apiKey {} registered with success: {} ", apiKeyDto);

        return apiKeyDto;
    }
}
