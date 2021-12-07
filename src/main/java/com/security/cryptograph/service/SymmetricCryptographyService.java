package com.security.cryptograph.service;

import com.google.common.annotations.VisibleForTesting;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
@Slf4j
public class SymmetricCryptographyService {

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String ALGORITHM_ENCRYPTATION = "AES";
    private Cipher cipher;

    @Autowired
    @SneakyThrows
    public SymmetricCryptographyService() {
        this.cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
    }

    @VisibleForTesting
    protected SymmetricCryptographyService(Cipher cipher) {
        this.cipher = cipher;
    }

    public SealedObject encryptObject(String algorithm, Serializable object, SecretKey key,
        IvParameterSpec iv) throws Exception {
        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return new SealedObject(object, cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
            InvalidKeyException | IOException | IllegalBlockSizeException e) {
            log.error("Error on object encrypt {}.", object, e);
            throw new Exception("Impossible encrypt the object!");
        }
    }

    public Serializable decryptObject(String algorithm, SealedObject sealedObject, SecretKey key,
        IvParameterSpec iv) throws Exception {
        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return (Serializable) sealedObject.getObject(cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
            InvalidKeyException | IOException | IllegalBlockSizeException e) {
            log.error("Error on decrypt the object {}.", sealedObject, e);
            throw new Exception("Impossible to decrypt the object!");
        }
    }

    public String encryptText(String input, SecretKey key, IvParameterSpec iv) throws Exception {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] cipherText = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException
            | IllegalBlockSizeException e) {
            log.error("Error on encrypt text {}.", input, e);
            throw new Exception("Impossible to encrypt text!");
        }
    }

    public String decryptText(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(plainText);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException
            | IllegalBlockSizeException e) {
            log.error("Error on decrypt text {}.", cipherText, e);
            throw new Exception("Impossible to decrypt text!");
        }
    }

    public SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_ENCRYPTATION);
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
