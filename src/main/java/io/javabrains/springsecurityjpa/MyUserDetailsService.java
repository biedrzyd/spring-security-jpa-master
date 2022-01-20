package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.MyUserDetails;
import io.javabrains.springsecurityjpa.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
public class MyUserDetailsService implements UserDetailsService {

    public static final int MAX_FAILED_ATTEMPTS = 3;
    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        if(userName.matches("^[a-zA-Z0-9]*$")) {
            Optional<User> user = userRepository.findByUserName(userName);

            user.orElseThrow(() -> new UsernameNotFoundException("Not found: " + userName));

            return user.map(MyUserDetails::new).get();
        } else {
            return (UserDetails) new UsernameNotFoundException("Regex violate");
        }
    }

    public void addUser(User user) {
        if(user.getUserName().matches("^[a-zA-Z0-9]*$")) {
            userRepository.save(user);
        }
    }

    public User getUserById(int id) {
        Optional<User> user = userRepository.findById(id);
        user.orElseThrow(() -> new UsernameNotFoundException("Not found: " + id));
        return user.get();
    }

    public void setUserPassword(int id, String password) {
        userRepository.findById(id).get().setPassword(password);
    }

    public User getUserByUserName(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElse(null);
    }

    public void increaseFailedAttempt(User user) {
        int newFailedAttempts = user.getFailedAttempt() + 1;
        userRepository.updateFailedAttempt(newFailedAttempts, user.getUserName());
    }

    public void lock(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(new Date());

        userRepository.save(user);
    }
}
