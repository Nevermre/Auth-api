package br.com.e.authentication.security;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
  private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
  @Value("${app.jwtSecret}")
  private String jwtSecret;
  @Value("${app.jwtExpirationInMs}")
  private int jwtExpirationInMs;

  public String generateToken(AuthModel authModel, String username, List<String> roleList, String embeddedToken, String authObject, String name) {

    if (name == null || name.isEmpty())
      name = username;

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

    byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    var key = Keys.hmacShaKeyFor(keyBytes);

    return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(expiryDate)
        .claim("authModel", authModel.GetModel())
        .claim("username", username)
        .claim("name", name)
        .claim("authObject", authObject)
        .claim("roles", roleList)
        .claim("embeddedToken", embeddedToken)
        .signWith(key, SignatureAlgorithm.HS512)
        .compact();
  }

  public String getUsername(String token) {
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(jwtSecret)
        .build()
        .parseClaimsJws(token)
        .getBody();

    return claims.get("username", String.class);
  }

  public List<String> getRoles(String token) {
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(jwtSecret)
        .build()
        .parseClaimsJws(token)
        .getBody();

    return (List<String>) claims.get("roles");
  }  

  public String getAuthObject(String token) {
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(jwtSecret)
        .build()
        .parseClaimsJws(token)
        .getBody();

    return claims.get("authObject", String.class);
  }

  public String getEmbeddedToken(String token) {
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(jwtSecret)
        .build()
        .parseClaimsJws(token)
        .getBody();

    return claims.get("embeddedToken", String.class);
  }

  public AuthModel getAuthModel(String token) {

    Claims claims = Jwts.parserBuilder()
        .setSigningKey(jwtSecret)
        .build()
        .parseClaimsJws(token)
        .getBody();

        var authModel = claims.get("authModel", String.class);

    return AuthModel.valueOf(authModel);
  }

  public boolean validateToken(String authToken) {
    try {
      Jwts.parserBuilder()
          .setSigningKey(jwtSecret)
          .build()
          .parseClaimsJws(authToken);

      return true;
    } catch (MalformedJwtException ex) {
      logger.error("Invalid JWT token");
    } catch (ExpiredJwtException ex) {
      logger.error("Expired JWT token");
    } catch (UnsupportedJwtException ex) {
      logger.error("Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
      logger.error("JWT claims string is empty.");
    }
    return false;
  }
}
