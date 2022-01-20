package io.javabrains.springsecurityjpa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Service
public class MyBcrypt implements PasswordEncoder {

    private final Pattern BCRYPT_PATTERN;
    private final Log logger;
    private final int strength;
    private final SecureRandom random;
    private String pepper;
    private final int pepperLength = 2;

    public MyBcrypt() {
        this(-1);
    }

    public MyBcrypt(int strength) {
        this(strength, null);
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

    private void setPepper() throws IOException {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("src/main/resources/pepper.txt"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        assert reader != null;
        pepper = reader.readLine();
        if(!(pepper.length() == pepperLength)){
            throw new IllegalArgumentException("Zla dlugosc pieprzu");
        }
    }

    public String encode(CharSequence rawPassword) {
        if(pepper == null) {
            try {
                setPepper();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        rawPassword += pepper;
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
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
        if (encodedPassword != null && encodedPassword.length() != 0) {
            if (!this.BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
                this.logger.warn("Encoded password does not look like BCrypt");
                return false;
            } else {
                boolean matches = false;
                for (int k = 65; k < 97; k++) {
                    for (int i = 65; i < 97; i++) {
                        String passwordWithPepper = rawPassword + String.valueOf((char) i) + String.valueOf((char) k);
                        if (BCrypt.checkpw(passwordWithPepper, encodedPassword)) {
                            matches = true;
                            break;
                        }
                    }
                    if(matches)
                        break;
                }
                return matches;
            }
        } else {
            this.logger.warn("Empty encoded password");
            return false;
        }
    }
}
