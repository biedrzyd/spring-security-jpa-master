package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.*;
import org.apache.commons.logging.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.crypto.NoSuchPaddingException;
import javax.validation.Valid;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Controller
public class HomeResource {

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

    private static final int passwordResetLength = 30;

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
        if (entropy == 0.0) {
            System.out.println(entropy);
            user.setPassword(String.valueOf(entropy));
            model.addAttribute("user", user);
            model.addAttribute("entropy", entropy);
            return "weak_pass";
        }
        String hashedPassword = bcrypt.encode(user.getPassword());
        user.setPassword(hashedPassword);
        if(!isValidUserName(user.getUserName()) || !isValidPassword(user.getPassword())){
            return "wrong_regex";
        }
        if (service.getUserByUserName(user.getUserName()) == null) {
            String passwordreset = generateRandomString(passwordResetLength);
            model.addAttribute("passwordreset", passwordreset);
            user.setPasswordReset(passwordreset);
            service.addUser(user);
            model.addAttribute("entropy", entropy);
            return "register_success";
        } else
            return "user_exists";
    }

    public static boolean isValidUserName (String s){
        return (s.matches("^[a-zA-Z0-9]*$"));
    }
    public static boolean isValidPassword (String s){
        return (s.matches("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"));
    }
    public static boolean isValidPasswordReset(String s){
        if(s.length() != passwordResetLength)
            return false;
        return (s.matches("^[a-zA-Z0-9]*$"));
    }

    @GetMapping("/wp")
    public String wrongPassword() {
        return "wp";
    }

    @GetMapping("/wrongregex")
    public String wrongRegex() {
        return "wrong_regex";
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
    public String addpassword(@ModelAttribute("user") CreateNewPassword password) throws NoSuchPaddingException, NoSuchAlgorithmException {
        if (Objects.isNull(getCurrentUserId())) {
            return "not_logged";
        }
        String encryptingPassword = padding(password.getDecryptpass());
        AES.setKey(encryptingPassword);

        Password passwordToSave = new Password();
        passwordToSave.setPassword(AES.encryptCBC(password.getPassword()));
        passwordToSave.setUserid((Integer) getCurrentUserId());
        passwordToSave.setSite(password.getSite());
        passwordDAO.save(passwordToSave);

        return "password_added";
    }

    @GetMapping(value = "/")
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
        if (Objects.isNull(getCurrentUserId())) {
            return "not_logged";
        } else {
            currentUserId = (int) getCurrentUserId();
        }
        for (Password p : passwordList
        ) {
            if (p.getUserid().equals(currentUserId)) {
                p.setPassword(AES.decryptCBC(p.getPassword(), decryptPass));
            } else {
                passwordsToRemove.add(p);
            }
        }
        passwordList.removeAll(passwordsToRemove);
        model.addAttribute("passwordList", passwordList);
        model.addAttribute("Password", new Password());
        return "password_list";
    }

    private Object getCurrentUserId() {
        String currentUserName = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            currentUserName = authentication.getName();
        }
        if (currentUserName == null)
            return null;
        Optional<User> userList = userRepository.findByUserName(currentUserName);
        if (!userList.isPresent()) {
            return null;
        } else return userList.get().getId();
    }

    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public String admin() {
        return ("<h1>Welcome Admin</h1>");
    }

    private String padding(String password) {
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
        if(!isValidUserName(user.getUserName())){
            return "wrong_regex";
        }
        if (Objects.isNull(getCurrentUserId())) {
            return "not_logged";
        } else {
            currentUserId = (int) getCurrentUserId();
        }
        Optional<User> userList = userRepository.findById(currentUserId);
        if (!user.getNewPassword().equals(user.getConfirmPassword()) || !bcrypt.matches(user.getPassword(), userList.get().getPassword())) {
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
    public String forgotPassword(@ModelAttribute("user") User user, Model model) {
        if(!isValidUserName(user.getUserName()) || !isValidPasswordReset(user.getPasswordReset())){
            return "wrong_regex";
        }
        Optional<User> userList = userRepository.findByUserName(user.getUserName());
        String password = generateRandomString(20);
        String hashedPassword = bcrypt.encode(password);
        if(! userList.isPresent() ){
            return "user_does_not_exist";
        }
        model.addAttribute("password", password);
        userList.get().setPassword(hashedPassword);
        userRepository.save(userList.get());

        return "forgot_password_success";
    }

    @GetMapping("/loginhistory")
    public String loginHistory(Model model) {
        int id;
        if (Objects.isNull(getCurrentUserId())) {
            return "not_logged";
        } else {
            id = (int) getCurrentUserId();
        }
        model.addAttribute("id", id);

        List<LoginHistory> loginList = loginDAO.findAll();
        List<LoginHistory> loginToRemove = new ArrayList<>();
        for (LoginHistory l : loginList) {
            if (l.getUserid() != id) {
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

    private String generateRandomString(int n) {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        Random random = new Random();

        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(n)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }
}