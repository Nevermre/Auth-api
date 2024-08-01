package br.com.e.authentication.error;

import java.time.ZonedDateTime;

public class ErrorPayload {
  private final String message;
  private final ZonedDateTime timestamp;

  public ErrorPayload(String message, ZonedDateTime timestamp) {
    this.message = message;
    this.timestamp = timestamp;
  }

  public String getMessage() {
    return this.message;
  }

  public ZonedDateTime getTimestamp() {
    return this.timestamp;
  }
}
