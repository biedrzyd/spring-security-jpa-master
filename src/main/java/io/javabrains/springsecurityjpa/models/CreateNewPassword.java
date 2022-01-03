package io.javabrains.springsecurityjpa.models;

public class CreateNewPassword extends Password{
    public String getDecryptpass() {
        return decryptpass;
    }

    public void setDecryptpass(String decryptpass) {
        this.decryptpass = decryptpass;
    }

    private String decryptpass;
}
