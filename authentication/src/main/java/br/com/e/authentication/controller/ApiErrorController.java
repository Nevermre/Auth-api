package br.com.e.authentication.controller;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import br.com.e.authentication.error.custom.NotFound;

@Controller
public class ApiErrorController implements ErrorController {
  @RequestMapping("/error")
  public void HandleError(HttpServletRequest request) {
    throw new NotFound("Endpoint \"" + request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI) + "\" not found!");
  }
}
