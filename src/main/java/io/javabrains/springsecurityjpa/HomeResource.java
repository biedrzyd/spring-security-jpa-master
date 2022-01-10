package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.util.*;

@Controller
public class HomeResource {

    //TODO: dodawac pokazywanie kto jest zalogowany lub jezeli wylogowany
    @Autowired
    MyBcrypt bcrypt;

    @Autowired
    PasswordDAO passwordDAO;

    @Autowired
    LoginDAO loginDAO;

    @Autowired
    UserRepository userRepository;

    @Autowired
    MyUserDetailsService service;

    @GetMapping("/register")
    public String showForm(Model model) {
        User user = new User();
        model.addAttribute("user", user);

        return "register_form";
    }

    @PostMapping("/register")
    public String submitForm(@ModelAttribute("user") User user, Model model) {
        user.setActive(true);
        user.setRoles("ROLE_USER");
        double entropy = CreateNewPassword.calculateEntropy(user.getPassword());
        if(entropy == 0.0){
            System.out.println(entropy);
            user.setPassword(String.valueOf(entropy));
            model.addAttribute("user", user);
            model.addAttribute("entropy", entropy);
            return "weak_pass";
        }
        String hashedPassword = bcrypt.encode(user.getPassword());
        user.setPassword(hashedPassword);
        if(service.getUserByUserName(user.getUserName()) == null) {
            service.addUser(user);
            model.addAttribute("entropy", entropy);
            return "register_success";
        }
        else
            return "user_exists";
    }

    @GetMapping("/wp")
    public String wrongPassword() {
        return "wp";
    }

    @GetMapping("/locked")
    public String accountLocked() {
        return "locked";
    }

    @GetMapping("/addpassword")
    public String addpassword(Model model) {
        CreateNewPassword password = new CreateNewPassword();
        model.addAttribute("password", password);

        return "add_password";
    }

    @PostMapping("/addpassword")
    public String addpassword(@ModelAttribute("user") CreateNewPassword password) {
        String encryptingPassword = padding(password.getDecryptpass());
        AES.setKey(encryptingPassword);

        Password passwordToSave = new Password();
        passwordToSave.setPassword(AES.encrypt(password.getPassword()));
        passwordToSave.setUserid((Integer) getCurrentUserId());
        passwordToSave.setSite(password.getSite());
        passwordDAO.save(passwordToSave);

        return "password_added";
    }

    @GetMapping(value="/")
    public String home(Model model) {
        User user = new User();
        model.addAttribute("user", user);

        String currentUserName = "niezalogowany";
        boolean logged = false;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            currentUserName = authentication.getName();
        }
        model.addAttribute("currentUserName", currentUserName);

        return "index";
    }

    @GetMapping("/passwords")
    public String user(@ModelAttribute("user") User user, Model model) {
        List<Password> passwordList = passwordDAO.findAll();
        List<Password> passwordsToRemove = new ArrayList<>();
        String decryptPass = user.getPassword();
        decryptPass = padding(decryptPass);
        int currentUserId;
        if(Objects.isNull(getCurrentUserId())){
            return "not_logged";
        } else{
            currentUserId = (int) getCurrentUserId();
        }
        for (Password p: passwordList
        ) {
            if(p.getUserid().equals(currentUserId)) {
                p.setPassword(AES.decrypt(p.getPassword(), decryptPass));
            } else {
                passwordsToRemove.add(p);
            }
        }
        passwordList.removeAll(passwordsToRemove);
        model.addAttribute("passwordList", passwordList);
        model.addAttribute("Password",new Password());
        return "password_list";
    }

    private Object getCurrentUserId(){
        String currentUserName = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            currentUserName = authentication.getName();
        }
        if(currentUserName == null)
            return null;
        Optional<User> userList = userRepository.findByUserName(currentUserName);
        if(!userList.isPresent()){
            return null;
        }
        else return userList.get().getId();
    }

    @RequestMapping(value="/admin", method=RequestMethod.GET)
    public String admin() {
        return ("<h1>Welcome Admin</h1>");
    }

    private String padding(String password){
        StringBuilder passwordBuilder = new StringBuilder(password);
        while (passwordBuilder.length() < 16)
            passwordBuilder.append("a");
        String encryptingPassword = passwordBuilder.toString();
        while (encryptingPassword.length() > 16)
            encryptingPassword = encryptingPassword.substring(0, encryptingPassword.length() - 1);
        return encryptingPassword;
    }

    @GetMapping("/changepassword")
    public String changePassword(Model model) {
        ChangePassword user = new ChangePassword();
        model.addAttribute("user", user);

        return "change_password";
    }

    @PostMapping("/changepassword")
    public String changePassword(@ModelAttribute("user") ChangePassword user) {
        int currentUserId;
        if(Objects.isNull(getCurrentUserId())){
            return "not_logged";
        } else{
            currentUserId = (int) getCurrentUserId();
        }
        Optional<User> userList = userRepository.findById(currentUserId);
        if(!user.getNewPassword().equals(user.getConfirmPassword()) || !bcrypt.matches(user.getPassword(), userList.get().getPassword())) {
            return "password_change_failure";
        }
        userList.get().setPassword(user.getConfirmPassword());
        service.setUserPassword(currentUserId, bcrypt.encode(user.getConfirmPassword()));
        userRepository.save(userList.get());
        return "password_change_success";
    }

    @GetMapping("/forgotpassword")
    public String forgotPassword(Model model) {
        User user = new User();
        model.addAttribute("user", user);

        return "forgot_password";
    }

    @PostMapping("/forgotpassword")
    public String forgotPassword(@ModelAttribute("user") User user) {
        Optional<User> userList = userRepository.findByUserName(user.getUserName());
        String password = "password123";
        String hashedPassword = bcrypt.encode(password);
        userList.get().setPassword(hashedPassword);
        //TODO: tylko jezeli nie ma takiej nazwy
        userRepository.save(userList.get());

        return "forgot_password_success";
    }

    @GetMapping("/loginhistory")
    public String loginHistory(Model model) {
        int id;
        if(Objects.isNull(getCurrentUserId())){
            return "not_logged";
        } else{
            id = (int) getCurrentUserId();
        }
        model.addAttribute("id", id);

        List<LoginHistory> loginList = loginDAO.findAll();
        List<LoginHistory> loginToRemove = new ArrayList<>();
        for (LoginHistory l: loginList) {
            if(l.getUserid() != id) {
                loginToRemove.add(l);
            }
        }
        loginList.removeAll(loginToRemove);
        model.addAttribute("loginList", loginList);
        model.addAttribute("LoginHistory", new LoginHistory());
        return "login_history";
    }

    @GetMapping("/logged")
    public String redirectWithUsingForwardPrefix() {
        LoginHistory loginHistory = new LoginHistory();
        loginHistory.setUserid((int) getCurrentUserId());
        loginHistory.setTime(new Date());
        loginDAO.save(loginHistory);
        return "login_success";
    }
}