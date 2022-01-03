package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.Password;
import io.javabrains.springsecurityjpa.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Controller
public class HomeResource {

    @Autowired
    MyBcrypt bcrypt;

    @Autowired
    PasswordDAO passwordDAO;

    @Autowired
    UserRepository userRepository;

    @Autowired
    MyUserDetailsService service;

    @GetMapping("/pass")
    public String showForm(String pass) {
        return pass;
    }

    @GetMapping("/register")
    public String showForm(Model model) {
        User user = new User();
        model.addAttribute("user", user);

        return "register_form";
    }

    @PostMapping("/register")
    public String submitForm(@ModelAttribute("user") User user) {
        user.setActive(true);
        user.setRoles("ROLE_USER");
        String hashedPassword = bcrypt.encode(user.getPassword());
        user.setPassword(hashedPassword);
        service.addUser(user);

        return "register_success";
    }

    @GetMapping(value="/")
    public String home() {
        return "index";
    }

    @GetMapping("/passwords")
    public String user(Model model) {
        List<Password> passwordList = passwordDAO.findAll();
        List<Password> passwordsToRemove = new ArrayList<>();
        int currentUserId = getCurrentUserId();
        for (Password p: passwordList
        ) {
            if(p.getUserid().equals(currentUserId)) {
                p.setPassword(AES.decrypt(p.getPassword(), "passwordpassword"));
            } else {
                passwordsToRemove.add(p);
            }
        }
        passwordList.removeAll(passwordsToRemove);
        model.addAttribute("passwordList", passwordList);
        return "password_list";
    }

    private int getCurrentUserId(){
        String currentUserName = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            currentUserName = authentication.getName();
        }
        Optional<User> userList = userRepository.findByUserName(currentUserName);
        return userList.get().getId();
        //return 5;
    }

/*    @RequestMapping(value="/passwords")
    public String user() {
        currentUserId = getCurrentUserId();

        StringBuilder html = new StringBuilder();
        List<Password> passwordList = passwordDAO.findAll();
        for (Password p: passwordList
             ) {
            if(p.getUserid().equals(currentUserId)) {
                html.append(AES.decrypt(p.getPassword(), "passwordpassword"));
                html.append("<br>");
            }
        }
        return html.toString();
        //return "password_list";
    }*/

    @RequestMapping(value="/admin", method=RequestMethod.GET)
    public String admin() {
        return ("<h1>Welcome Admin</h1>");
    }


}