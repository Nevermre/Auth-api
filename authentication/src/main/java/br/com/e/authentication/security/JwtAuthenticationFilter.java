package br.com.e.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.e.authentication.error.custom.NotFound;
import br.com.e.authentication.model.Role;
import br.com.e.authentication.model.User;
import br.com.e.authentication.repository.ApiKeyRep;
import br.com.e.authentication.repository.UserRep;
import lombok.extern.slf4j.Slf4j;
import reactor.util.function.Tuple3;
import reactor.util.function.Tuples;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  @Autowired
  private UserRep userRepository;
  @Autowired
  private ApiKeyRep apiKeyRep;
  @Autowired
  private JwtTokenProvider tokenProvider;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
        
    log.debug("[doFilterInternal] request URI: {}", request.getRequestURI());
    log.debug("[doFilterInternal] RemoteHost: {}", request.getRemoteHost());

    if (request.getRequestURI().endsWith("/login/astra"))
    {
      log.debug("Filtering /login/astra");
      filterChain.doFilter(request, response);
      return;
    }

    if (request.getRequestURI().contains("/login/dte"))
    {
      log.debug("Filtering /login/dte");
      filterChain.doFilter(request, response);
      return;
    }

    var headers = getHeadersFromRequest(request);

    var appCode = headers.getT1();
    var jwt = headers.getT2();
    var apiKey = headers.getT3();

    log.debug("[doFilterInternal] appCode: {}", appCode);
    log.debug("[doFilterInternal] jwt: {}", jwt);
    log.debug("[doFilterInternal] apiKey: {}", apiKey);

    if (StringUtils.hasText(apiKey))
      authByApiKey(request, response, filterChain, appCode, apiKey);
    else
      if (StringUtils.hasText(jwt))
        authByJwtToken(request, response, filterChain, jwt);
      else
        filterChain.doFilter(request, response);
      
      return;
  }

  private void authByApiKey(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain,
      String appCode, String apiKey) throws IOException, ServletException {

        //must have both
        if (!StringUtils.hasText(appCode) && !StringUtils.hasText(apiKey)) {
          filterChain.doFilter(request, response);
          return;
        }

        var apiKeyObj = apiKeyRep.findByApikey(apiKey);

        if (!apiKeyObj.isPresent())
          throw new BadCredentialsException("ApiKey not found.");

        log.debug("[authByApiKey] apikey is present {}", apiKeyObj.get());

        if (!apiKeyObj.get().getActive())
          throw new BadCredentialsException("ApiKey is not active.");          

        var apps = apiKeyObj.get().getApps();

        var app = apps.stream().filter(x -> x.getAppcode().equals(appCode)).findFirst();

        if (!app.isPresent())
          throw new BadCredentialsException("Invalid ApiKey Credential");
        
        log.debug("[authByApiKey] app is present {}", app);

        var roleList = apps.stream().map(x -> new Role("ROLE_APP_" + x.getAppcode(),"Dynamic role for app " + x.getAppname())).toList();
        log.debug("[authByApiKey] Dynamic role: {}", roleList);
   
        UserDetails userDetails = new User(AuthModel.ApiKeyAuthModel.name() + ":" + apiKeyObj.get().getApikey(), apiKeyObj.get().getApikey(), apiKeyObj.get().getKeyname(), apiKeyObj.get().getApikey());
    
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, roleList);
    
        authentication.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));
    
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
  }

  private void authByJwtToken(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, String jwt)
      throws IOException, ServletException {

    if (!(StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt))) {
      filterChain.doFilter(request, response);
      return;
    }

    var username = tokenProvider.getUsername(jwt);
    var authModel = tokenProvider.getAuthModel(jwt);
    var roles = tokenProvider.getRoles(jwt);
    var roleList = roles.stream().map(x -> new Role(x,x)).toList();
    var authObject = tokenProvider.getAuthObject(jwt);

    UserDetails userDetails = authModel == AuthModel.UsernameAuthModel
        ? userRepository.findByUsername(username)
            .orElseThrow(() -> new NotFound("User not found with username: " + username))
        : new User(authModel + ":" + username + ":" + authObject, username, username, username);

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
        authModel == AuthModel.UsernameAuthModel ? userDetails.getAuthorities() : roleList);

    authentication.setDetails(
        new WebAuthenticationDetailsSource().buildDetails(request));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    filterChain.doFilter(request, response);
  }

  private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");

    log.debug("request header 'Authorization': {}", bearerToken);

    if (!(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")))
      return null;

    return bearerToken.substring(7, bearerToken.length());
  }

  private Tuple3<String, String, String> getHeadersFromRequest(HttpServletRequest request) {

    var appCode = request.getHeader("X-APP-CODE");
    var bearerToken = request.getHeader("Authorization");
    var apiKey = request.getHeader("X-API-KEY");

    if ((StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")))
      bearerToken = bearerToken.substring(7, bearerToken.length());

    if (appCode == null) appCode = "";
    if (bearerToken == null) bearerToken = "";
    if (apiKey == null) apiKey = "";

    return Tuples.of(appCode, bearerToken, apiKey);

  }
}
