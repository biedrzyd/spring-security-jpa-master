package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.MyUserDetails;

import io.javabrains.springsecurityjpa.models.User;
import io.javabrains.springsecurityjpa.models.UserPasswords;
import io.javabrains.springsecurityjpa.models.UserPasswordsDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MyUserPasswordsService {

    @Autowired
    UserPasswordRepository userRepository;

    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        Optional<UserPasswords> userPasswords = userRepository.getTasksByUserId(5);

        userPasswords.orElseThrow(() -> new UsernameNotFoundException("Not found: " + userName));

        return userPasswords.map(UserPasswordsDetails::new).get();
    }
}
