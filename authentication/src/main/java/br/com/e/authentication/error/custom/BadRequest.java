package br.com.e.authentication.error.custom;

import java.time.ZoneId;
import java.time.ZonedDateTime;

import org.springframework.http.HttpStatus;

import br.com.e.authentication.error.ApiError;
import br.com.e.authentication.error.ErrorPayload;

public class BadRequest extends ApiError {
  public BadRequest(String message) {
    super(HttpStatus.BAD_REQUEST, message);
  }

  public ErrorPayload serializeError() {
    return new ErrorPayload(this.getMessage(), ZonedDateTime.now(ZoneId.of("Z")));
  }

  public HttpStatus getStatusCode() {
    return this.statusCode;
  }
}
