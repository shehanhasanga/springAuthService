package shehan.auth.authserver.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import shehan.auth.authserver.constants.SecurityConstant;
import shehan.auth.authserver.domain.HttpResponse;
import shehan.auth.authserver.domain.User;
import shehan.auth.authserver.domain.UserPrincipal;
import shehan.auth.authserver.exceptions.domain.ExceptionHandling;
import shehan.auth.authserver.service.UserService;
import shehan.auth.authserver.utilities.JWTTokenProvider;

import javax.jws.soap.SOAPBinding;

@RestController
@RequestMapping(value = "/user")
public class UserController extends ExceptionHandling {
    private UserService userService;
    private AuthenticationManager authenticationManager;
    private JWTTokenProvider jwtTokenProvider;


    @Autowired
    public UserController(UserService userService,AuthenticationManager authenticationManager, JWTTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) throws Exception{
        User newUser = userService.register(user.getFirsrtName(), user.getLastName(), user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) throws Exception{
        authenticateUser(user.getUsername(), user.getPassword());
        User userSaved = userService.findByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(userSaved);
        HttpHeaders jwtHeaders = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(userSaved, jwtHeaders, HttpStatus.OK);
    }

    private void authenticateUser(String userName, String password){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName, password));

    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal){
        HttpHeaders headers = new HttpHeaders();
        headers.add(SecurityConstant.JWT_TOKEN_HEADER, jwtTokenProvider.generateJWTToken(userPrincipal));
        return headers;
    }
}
