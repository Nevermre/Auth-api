package br.com.e.authentication.error;

import javax.persistence.NoResultException;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import br.com.e.authentication.dto.DataResponseDto;
import br.com.e.authentication.error.custom.BadRequest;
import br.com.e.authentication.error.custom.InternalError;
import br.com.e.authentication.error.custom.NotFound;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@ControllerAdvice
public class ErrorHandler extends ResponseEntityExceptionHandler {

  @ExceptionHandler(value = { ApiError.class })
  public ResponseEntity<Object> apiErrorHandler(ApiError error) {
    return ResponseEntity.status(error.getStatusCode()).body(new DataResponseDto<ErrorPayload>(error.serializeError()));
  }

  @ExceptionHandler(value = { BadCredentialsException.class })
  public ResponseEntity<Object> badCredentialsHandler(BadCredentialsException error) {
    BadRequest badRequest = new BadRequest("invalid user or password!");
    log.debug("invalid user or password");

    return ResponseEntity.status(badRequest.getStatusCode())
        .body(new DataResponseDto<ErrorPayload>(badRequest.serializeError()));
  }

  @ExceptionHandler(value = { EmptyResultDataAccessException.class })
  public ResponseEntity<Object> noResultExceptionHandler(NoResultException error) {
    NotFound notFound = new NotFound(error.getMessage());
    return ResponseEntity.status(notFound.getStatusCode())
        .body(new DataResponseDto<ErrorPayload>(notFound.serializeError()));
  }

  @ExceptionHandler(value = { RuntimeException.class })
  public ResponseEntity<Object> exceptionHandler(Exception error) {
    error.printStackTrace();
    InternalError internalError = new InternalError(error.getMessage());
    return ResponseEntity.status(internalError.getStatusCode())
        .body(new DataResponseDto<ErrorPayload>(internalError.serializeError()));
  }
}
