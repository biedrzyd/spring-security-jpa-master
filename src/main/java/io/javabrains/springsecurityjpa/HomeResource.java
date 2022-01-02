package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.Password;
import io.javabrains.springsecurityjpa.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
public class HomeResource {

    @Autowired
    PasswordDAO passwordDAO;

    @Autowired
    UserRepository userRepository;
    @GetMapping(value="/")
    public String home() {
        String html="<input></input>";
        html += "<input type=submit></input>";
        return html;
    }


/*    @GetMapping("/pass")
    public String showForm() {
        return "pass_form";
    }*/

    @GetMapping("/passwords")
    public String user() {
        String currentUserName = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            currentUserName = authentication.getName();
        }

        List<Password> passwordList = passwordDAO.findAll();
        Optional<User> userList = userRepository.findByUserName(currentUserName);
        Integer currentUserId = userList.get().getId();

        StringBuilder html = new StringBuilder();

        //SecretKey secretKey = AESUtil.getK
        for (Password p: passwordList
             ) {
            if(p.getUserid().equals(currentUserId)) {
                html.append(AES.decrypt(p.getPassword(), "passwordpassword"));
                html.append("<br>");
            }
        }
        return html.toString();
    }

    @GetMapping("/admin")
    public String admin() {
        return ("<h1>Welcome Admin</h1>");
    }

}

