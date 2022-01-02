package io.javabrains.springsecurityjpa;

import javax.crypto.*;
import javax.crypto.Cipher;
import org.apache.tomcat.util.codec.binary.Base64;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES {
    static  byte[]  key = "passwordpassword".getBytes();
    final static String algorithm="AES";

    public static String encrypt(String data){

        byte[] dataToSend = data.getBytes();
        Cipher c = null;
        try {
            c = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        SecretKeySpec k =  new SecretKeySpec(key, algorithm);
        try {
            c.init(Cipher.ENCRYPT_MODE, k);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] encryptedData = "".getBytes();
        try {
            encryptedData = c.doFinal(dataToSend);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        byte[] encryptedByteValue =    new Base64().encode(encryptedData);
        return  new String(encryptedByteValue);//.toString();
    }

    public static String decrypt(String data, String password){
        key = password.getBytes();
        byte[] encryptedData  = new Base64().decode(data);
        Cipher c = null;
        try {
            c = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        SecretKeySpec k =
                new SecretKeySpec(key, algorithm);
        try {
            c.init(Cipher.DECRYPT_MODE, k);
        } catch (InvalidKeyException e1) {
            e1.printStackTrace();
        }
        byte[] decrypted = null;
        try {
            decrypted = c.doFinal(encryptedData);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return new String(decrypted);
    }

    public static void main(String[] args){
        String loginPassword = "passwordpassword";
        AES AES = new AES();
        String password= AES.encrypt("password3");
        System.out.println(password);
        System.out.println(AES.decrypt(password, loginPassword));
    }
}