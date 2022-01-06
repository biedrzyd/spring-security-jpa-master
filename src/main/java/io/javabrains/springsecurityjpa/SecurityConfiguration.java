package io.javabrains.springsecurityjpa;

import com.sun.org.apache.xml.internal.security.algorithms.implementations.SignatureDSA;
import com.sun.org.apache.xml.internal.security.signature.XMLSignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import sun.security.rsa.RSASignature;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomLoginFailureHandler loginFailureHandler;
    @Autowired
    UserDetailsService userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasAnyRole("ADMIN", "USER")
                .antMatchers("/").permitAll()
                .and().
                formLogin()
                //.loginPage("/login")
                .failureHandler(loginFailureHandler)
                .usernameParameter("username")
                .permitAll();

    }
}
