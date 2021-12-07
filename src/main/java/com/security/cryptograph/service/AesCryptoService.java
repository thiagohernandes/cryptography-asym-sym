package com.security.cryptograph.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

@Slf4j
@Service
public class AesCryptoService {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int IV_SIZE = 128;
    private static final int IV_LENGTH = IV_SIZE / 4;
    private static final DataTypeEnum DATA_TYPE = DataTypeEnum.BASE64;
    private static final String AES_ALGORITHM = "AES";
    private int keySize = 256;
    private int iterationCount = 1989;
    private Cipher cipher;
    private int saltLength;

    public AesCryptoService() {
        try {
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            saltLength = this.keySize / 4;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            log.error("Constructor error - AesCryptoService ", e);
        }
    }

    public AesCryptoService(int keySize, int iterationCount) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.keySize = keySize;
        this.iterationCount = iterationCount;
        cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        saltLength = this.keySize / 4;
    }

    private static byte[] generateRandom(int length) {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        return randomBytes;
    }

    private static byte[] fromBase64(String str) {
        return DatatypeConverter.parseBase64Binary(str);
    }

    private static String toBase64(byte[] ba) {
        return DatatypeConverter.printBase64Binary(ba);
    }

    private static byte[] fromHex(String str) {
        return DatatypeConverter.parseHexBinary(str);
    }

    private static String toHex(byte[] ba) {
        return DatatypeConverter.printHexBinary(ba);
    }

    public String encrypt(String passphrase, String plainText) throws Exception {
        String salt = toHex(generateRandom(keySize / 8));
        String iv = toHex(generateRandom(IV_SIZE / 8));
        String cipherText = handleEncrypt(salt, iv, passphrase, plainText);
        return salt + iv + cipherText;
    }

    public String decrypt(String passPhrase, String cipherText) throws Exception {
        final String msg = "Error on decrypt";
        try {
            String salt = cipherText.substring(0, saltLength);
            String iv = cipherText.substring(saltLength, saltLength + IV_LENGTH);
            String ct = cipherText.substring(saltLength + IV_LENGTH);
            return handleDecrypt(salt, iv, passPhrase, ct);
        } catch (Exception e) {
            log.error(msg, e);
            throw new Exception(msg);
        }
    }

    private String handleEncrypt(String salt, String iv, String passPhrase, String plainText) throws Exception {
        SecretKey key = generateKey(salt, passPhrase);
        byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, key, iv, plainText.getBytes(StandardCharsets.UTF_8));
        String cipherText;
        if (DATA_TYPE.equals(DataTypeEnum.HEX)) {
            cipherText = toHex(encrypted);
        } else {
            cipherText = toBase64(encrypted);
        }
        return cipherText;
    }

    private String handleDecrypt(String salt, String iv, String passPhrase, String cipherText) throws Exception {
        SecretKey key = generateKey(salt, passPhrase);
        byte[] encrypted;
        if (DATA_TYPE.equals(DataTypeEnum.HEX)) {
            encrypted = fromHex(cipherText);
        } else {
            encrypted = fromBase64(cipherText);
        }
        byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private byte[] doFinal(int encryptMode, SecretKey key, String iv, byte[] bytes) throws Exception {
        cipher.init(encryptMode, key, new IvParameterSpec(fromHex(iv)));
        return cipher.doFinal(bytes);
    }

    private SecretKey generateKey(String salt, String passphrase) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), fromHex(salt), iterationCount, keySize);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES_ALGORITHM);
    }

    private enum DataTypeEnum {
        HEX,
        BASE64
    }

}
