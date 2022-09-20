package shehan.auth.authserver.service;

import shehan.auth.authserver.domain.User;

import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws Exception;
    List<User> getUsers();
    User findByUsername(String username);
    User findByEmail(String email);

}
