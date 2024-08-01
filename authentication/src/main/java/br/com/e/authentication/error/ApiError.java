package br.com.e.authentication.error;

import org.springframework.http.HttpStatus;

public abstract class ApiError extends RuntimeException {
  protected final HttpStatus statusCode;

  public ApiError(HttpStatus statusCode, String message) {
    super(message);
    this.statusCode = statusCode;
  }

  public abstract ErrorPayload serializeError();

  public HttpStatus getStatusCode() {
    return this.statusCode;
  }
}
