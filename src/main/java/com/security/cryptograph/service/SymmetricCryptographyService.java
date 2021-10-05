package com.security.cryptograph.service;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.annotations.VisibleForTesting;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SymmetricCryptographyService {

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String ALGORITHM_ENCRYPTATION = "AES";
    private final Cipher cipher;

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
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return new SealedObject(object, cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
            InvalidKeyException | IOException | IllegalBlockSizeException e) {
            log.error("Erro ao tentar criptografar o objeto {}.", object, e);
            throw new Exception("Impossível criptografar o objeto!");
        }
    }

    public Serializable decryptObject(String algorithm, SealedObject sealedObject, SecretKey key,
        IvParameterSpec iv) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return (Serializable) sealedObject.getObject(cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
            InvalidKeyException | IOException | IllegalBlockSizeException e) {
            log.error("Erro ao tentar descriptografar o objeto {}.", sealedObject, e);
            throw new Exception("Impossível descriptografar o objeto!");
        }
    }

    public String decryptText(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(plainText);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException
            | IllegalBlockSizeException e) {
            log.error("Erro ao tentar descriptografar o texto {}.", cipherText, e);
            throw new Exception("Impossível descriptografar o texto!");
        }
    }

    public String encryptText(String input, SecretKey key, IvParameterSpec iv) throws Exception {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] cipherText = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException
            | IllegalBlockSizeException e) {
            log.error("Erro ao tentar criptografar o texto {}.", input, e);
            throw new Exception("Impossível criptografar o texto!");
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
