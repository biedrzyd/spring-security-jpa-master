package io.javabrains.springsecurityjpa;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class AES {
    static byte[] key = "passwordpassword".getBytes();
    final static String algorithm = "AES";
    private static String initVector="1234567812345678";
    public static void setKey(String pass) {
        key = pass.getBytes();
    }

    public static String encrypt(String data) {

        byte[] dataToSend = data.getBytes();
        Cipher c = null;
        try {
            c = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        SecretKeySpec k = new SecretKeySpec(key, algorithm);
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
        byte[] encryptedByteValue = new Base64().encode(encryptedData);
        return new String(encryptedByteValue);//.toString();
    }

    public static String encryptCBC(String data) throws NoSuchPaddingException, NoSuchAlgorithmException {
        try{
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte [] encrypted = cipher.doFinal(data.getBytes());
            return DatatypeConverter.printBase64Binary(encrypted);
        } catch (InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decryptCBC(String data, String password){
        try{
            key = password.getBytes();
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec skeySpec = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte [] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(data));
            String decrypted = null;
            decrypted = new String(original);
            if(Objects.isNull(original))
                return "ENCRYPTED";
            return new String(original);
        } catch (NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e){
            return "ENCRYPTED";
        }
        return "ENCRYPTED";
    }

    public static String decrypt(String data, String password) {
        key = password.getBytes();
        byte[] encryptedData = new Base64().decode(data);
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
        if (Objects.isNull(decrypted))
            return "ENCRYPTED";
        return new String(decrypted);
    }

    public static void main(String[] args) {
        String loginPassword = "passwordpassword";
        AES AES = new AES();
        String password = encrypt("password3");
        System.out.println(password);
        System.out.println(decrypt(password, loginPassword));
    }
}