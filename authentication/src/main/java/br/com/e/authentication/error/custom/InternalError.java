package br.com.e.authentication.error.custom;

import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.springframework.http.HttpStatus;

import br.com.e.authentication.error.ApiError;
import br.com.e.authentication.error.ErrorPayload;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InternalError extends ApiError {
  public InternalError(String message) {
    super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    log.error("Internal Error, message: {}", this.getMessage());
  }

  public ErrorPayload serializeError() {
    return new ErrorPayload("Something went wrong!", ZonedDateTime.now(ZoneId.of("Z")));
  }

  public HttpStatus getStatusCode() {
    return this.statusCode;
  }
}
