package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomLoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Autowired
    private MyUserDetailsService userDetailsService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        if((!HomeResource.isValidUserName(username)) || (!HomeResource.isValidPassword(password))){
            super.setDefaultFailureUrl("/wrongregex");
            super.onAuthenticationFailure(request, response, exception);
            return;
        }
        User user = userDetailsService.getUserByUserName(username);
        if (user != null) {
            System.out.println("User failed to login" + username);
        } else {
            System.out.println("User with name " + username + " does not exist");
        }
        boolean locked = false;
        if (user != null) {
            if (user.isActive() && user.isAccountNonLocked()) {
                if (user.getFailedAttempt() < MyUserDetailsService.MAX_FAILED_ATTEMPTS - 1) {
                    userDetailsService.increaseFailedAttempt(user);
                } else {
                    userDetailsService.lock(user);
                    exception = new LockedException("Konto zablokowane z powodu 3 nieudanych prób logowania");
                }
            } else if (user.isActive() && !user.isAccountNonLocked()) {
                super.setDefaultFailureUrl("/locked");
                locked = true;
            }
        }
        if (!locked) {
            super.setDefaultFailureUrl("/wp");
        }
        super.onAuthenticationFailure(request, response, exception);
    }
}
