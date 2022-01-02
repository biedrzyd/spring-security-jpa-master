package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
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
/*
    @GetMapping(value="/")
    public String home() {
        String html = "<button onclick=\"getElementById('demo').innerHTML = Date()\">What is the time?</button>";
        html += "<p id=\"demo\"></p>";
        return html;
    }

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

        for (Password p: passwordList
             ) {
            if(p.getUserid().equals(currentUserId)) {
                html.append(AES.decrypt(p.getPassword(), "passwordpasswor1"));
                html.append("<br>");
            }
        }
        return html.toString();
    }

    @GetMapping("/admin")
    public String admin() {
        return ("<h1>Welcome Admin</h1>");
    }*/

}

