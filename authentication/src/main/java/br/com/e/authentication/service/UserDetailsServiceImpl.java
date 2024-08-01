package br.com.e.authentication.service;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.e.authentication.error.custom.InternalError;
import br.com.e.authentication.model.User;
import br.com.e.authentication.repository.UserRep;
import br.com.e.authentication.security.AuthModel;

@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

  @Autowired
  UserRep userRepository;
  private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

  @Override
  public UserDetails loadUserByUsername(String flaggedUsernameOrEmail)
      throws UsernameNotFoundException {

    var split = flaggedUsernameOrEmail.split(":");

    if (split.length != 2)
      throw new InternalError("Invalid authentication format!");

    var authModelStrig = split[0];

    var authModel = AuthModel.valueOf(authModelStrig);

    String usernameOrEmail = split[1];

    User user = authModel == AuthModel.UsernameAuthModel
        ? userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found with username or email : " + usernameOrEmail))
        : createGenericUser(usernameOrEmail);

    return user;
  }

  private User createGenericUser(String usernameOrEmail) {
    User user = new User(
        usernameOrEmail,
        usernameOrEmail,
        usernameOrEmail,
        passwordEncoder.encode(usernameOrEmail));
    return user;
  }
}