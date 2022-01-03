package io.javabrains.springsecurityjpa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.regex.Pattern;

@Service
public class MyBcrypt implements PasswordEncoder {

    private Pattern BCRYPT_PATTERN;
    private final Log logger;
    private final int strength;
    private final SecureRandom random;

    public MyBcrypt() {
        this(-1);
    }

    public MyBcrypt(int strength) {
        this(strength, (SecureRandom)null);
    }

    public MyBcrypt(int strength, SecureRandom random) {
        this.BCRYPT_PATTERN = Pattern.compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");
        this.logger = LogFactory.getLog(this.getClass());
        if (strength == -1 || strength >= 4 && strength <= 31) {
            this.strength = strength;
            this.random = random;
        } else {
            throw new IllegalArgumentException("Bad strength");
        }
    }

    public String encode(CharSequence rawPassword) {
        String salt;
        if (this.strength > 0) {
            if (this.random != null) {
                salt = BCrypt.gensalt(this.strength, this.random);
            } else {
                salt = BCrypt.gensalt(this.strength);
            }
        } else {
            salt = BCrypt.gensalt();
        }

        return BCrypt.hashpw(rawPassword.toString(), salt);
    }

    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword != null && encodedPassword.length() != 0) {
            if (!this.BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
                this.logger.warn("Encoded password does not look like BCrypt");
                return false;
            } else {
                boolean matches = false;
                StringBuilder rawPasswordBuilder = new StringBuilder(rawPassword);
                for(int i = 65; i < 97; i++){
                    String passwordWithPepper = rawPassword + String.valueOf((char) i);
                    if(BCrypt.checkpw(passwordWithPepper, encodedPassword)) {
                        matches = true;
                        break;
                    }
                }
                return matches;
            }
        } else {
            this.logger.warn("Empty encoded password");
            return false;
        }
    }
}
