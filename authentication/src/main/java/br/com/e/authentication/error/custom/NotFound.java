package br.com.e.authentication.error.custom;

import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.springframework.http.HttpStatus;

import br.com.e.authentication.error.ApiError;
import br.com.e.authentication.error.ErrorPayload;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NotFound extends ApiError {
  public NotFound(String message) {
    super(HttpStatus.NOT_FOUND, message);
    log.debug("Not Found, message: {}", this.getMessage());
  }

  public NotFound() {
    super(HttpStatus.NOT_FOUND, "Not Found");
    log.debug("Not Found, message: {}", this.getMessage());
  }

  public ErrorPayload serializeError() {
    return new ErrorPayload(this.getMessage(), ZonedDateTime.now(ZoneId.of("Z")));
  }

  public HttpStatus getStatusCode() {
    return this.statusCode;
  }
}
