package com.security.cryptograph.service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.annotations.VisibleForTesting;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AsymmetricCryptographyService {

    private static final String CIPHER_TRANSFORMATION_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private final Cipher cipher;

    @Autowired
    @SneakyThrows
    public AsymmetricCryptographyService() {
        this.cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_ALGORITHM);
    }

    @VisibleForTesting
    protected AsymmetricCryptographyService(Cipher cipher) {
        this.cipher = cipher;
    }

    public byte[] decrypt(String privateKeyBase64, byte[] value) throws Exception {
        try {
            PrivateKey privateKey = rebuildPrivateKey(privateKeyBase64);
            initCipherForDecryption(privateKey);
            return cipher.doFinal(value);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            log.error("Erro ao tentar descriptografar o valor {}.", value, e);
            throw new Exception("Impossível descriptografar o dado!");
        }
    }

    public byte[] decrypt(String privateKeyBase64, String encryptedValueBase64) throws Exception {
        final byte[] encryptedValue = Base64.getDecoder().decode(encryptedValueBase64);
        return decrypt(privateKeyBase64, encryptedValue);
    }

    private PrivateKey rebuildPrivateKey(String privateKeyBase64) throws Exception {
        byte[] decodedPrivateKey = Base64.getDecoder().decode(privateKeyBase64);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KeyPairService.KEY_ALGORITHM);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Error rebuilding private key.", e);
            throw new Exception("Erro ao tentar reconstruir a chave privada!");
        }
    }

    @SneakyThrows
    private void initCipherForDecryption(PrivateKey privateKey) {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    }

    public byte[] encrypt(String publicKeyBase64, byte[] value) throws Exception {
            PublicKey publicKey = rebuildPublicKey(publicKeyBase64);
            initCipherForEncryption(publicKey);
            return cipher.doFinal(value);
    }

    private PublicKey rebuildPublicKey(String publicKeyBase64) throws Exception {
        byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyBase64);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KeyPairService.KEY_ALGORITHM);
            return keyFactory.generatePublic(new X509EncodedKeySpec(decodedPublicKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Error rebuilding public key.", e);
            throw new Exception("Erro ao tentar reconstruir a chave pública!");
        }
    }

    @SneakyThrows
    private void initCipherForEncryption(PublicKey publicKey) {
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    }
}
