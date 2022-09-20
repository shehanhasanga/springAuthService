package shehan.auth.authserver.service.impl;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import shehan.auth.authserver.domain.Role;
import shehan.auth.authserver.domain.User;
import shehan.auth.authserver.domain.UserPrincipal;
import shehan.auth.authserver.exceptions.domain.EmailExistsException;
import shehan.auth.authserver.exceptions.domain.UserNotFoundException;
import shehan.auth.authserver.exceptions.domain.UsernameExsistsException;
import shehan.auth.authserver.repository.UserRepository;
import shehan.auth.authserver.service.UserService;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;

@Service
@Transactional
@Qualifier("UserDetailsService")
public class UserServiceImpl implements UserService, UserDetailsService {
    private UserRepository repository;
    private Logger logger = LoggerFactory.getLogger(getClass());
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImpl(UserRepository repository, BCryptPasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findUserByUsername(username);
        if(user == null){
            logger.error("User not found by username :" + username);
            throw new UsernameNotFoundException("User not found exception: " + username);
        } else {
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            repository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            logger.info("Returning found user by username: " + username);
            return userPrincipal;
        }
    }

    @Override
    public User register(String firstName, String lastName, String username, String email) throws Exception{
        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);
        User user = new User();
        user.setUserId(generateUserId());
        String password = generatePassword();
        String encodedPassword = encodePassword(password);
        user.setFirsrtName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodedPassword);
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(Role.ROLE_USER.name());
        user.setAuthorities(Role.ROLE_USER.getAuthorities());
        user.setProfileImageUrl(getTempImageUrl());
        repository.save(user);
        logger.info("new user password is : " + password);
        return user;
    }

    private String getTempImageUrl(){
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/image/profile/temp").toUriString();

    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String generateUserId(){
        return RandomStringUtils.randomNumeric(10);
    }

    private User validateNewUsernameAndEmail(String currentName, String newUserName, String newEmail) throws Exception{
        if(StringUtils.isNotBlank(currentName)){
            User currentUser = findByUsername(currentName);
            if(currentUser == null){
                throw new UserNotFoundException("No user found by the username: " + currentName);

            }
            User userNew = findByUsername(newUserName);
            if(userNew != null && !currentUser.getId().equals(userNew.getId())){
                throw new UsernameExsistsException("Username is already taken");
            }

            User userFromEmail = findByEmail(newEmail);
            if(userFromEmail != null && !currentUser.getId().equals(userFromEmail.getId())){
                throw new EmailExistsException("Email is already taken");
            }
            return currentUser;
        } else {
            User userFromName = findByUsername(newUserName);
            if(userFromName != null){
                throw new UsernameExsistsException("Username is already taken");
            }
            User userByEmail = findByEmail(newEmail);
            if(userByEmail != null){
                throw new EmailExistsException("Email is already taken");
            }
            return null;

        }
    }

    @Override
    public List<User> getUsers() {
        return repository.findAll();
    }

    @Override
    public User findByUsername(String username) {
        return repository.findUserByUsername(username);
    }

    @Override
    public User findByEmail(String email) {
        return repository.findUserByEmail(email);
    }
}
