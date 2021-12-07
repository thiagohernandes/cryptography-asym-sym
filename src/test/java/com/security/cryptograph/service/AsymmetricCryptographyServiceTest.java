package com.security.cryptograph.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.rsa.crypto.RsaAlgorithm;

import lombok.SneakyThrows;
import org.springframework.test.util.ReflectionTestUtils;


@RunWith(MockitoJUnitRunner.class)
public class AsymmetricCryptographyServiceTest {

    private static final byte[] SOME_DECRYPTED_VALUE = "decrypted_value".getBytes();
    private static final byte[] SOME_ENCRYPTED_VALUE = "abcdefgh".getBytes();

    private AsymmetricCryptographyService asymmetricCryptographyService;

    @Before
    @SneakyThrows
    public void setUp() {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        this.asymmetricCryptographyService = new AsymmetricCryptographyService(cipher);
    }

    @Test
    @SneakyThrows(value = NoSuchAlgorithmException.class)
    public void shouldEncryptAndDecryptCorrectly() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RsaAlgorithm.DEFAULT.getJceName());
        keyGen.initialize(2048);

        KeyPair validKeyPair = keyGen.generateKeyPair();
        String validPublicKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPublic().getEncoded());
        String validPrivateKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPrivate().getEncoded());

        byte[] encryptedBytes = asymmetricCryptographyService.encrypt(validPublicKeyBase64, SOME_DECRYPTED_VALUE);

        byte[] decryptedBytes = asymmetricCryptographyService.decrypt(validPrivateKeyBase64, encryptedBytes);

        assertThat(decryptedBytes, equalTo(SOME_DECRYPTED_VALUE));
    }

    @Test
    @SneakyThrows(value = NoSuchAlgorithmException.class)
    public void shouldEncryptAndDecryptCorrectlyValueInBase64() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RsaAlgorithm.DEFAULT.getJceName());
        keyGen.initialize(2048);

        KeyPair validKeyPair = keyGen.generateKeyPair();
        String validPublicKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPublic().getEncoded());
        String validPrivateKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPrivate().getEncoded());

        byte[] encryptedBytes = asymmetricCryptographyService.encrypt(validPublicKeyBase64, SOME_DECRYPTED_VALUE);
        String encryptedValueBase64 = Base64.getEncoder().encodeToString(encryptedBytes);

        byte[] decryptedBytes = asymmetricCryptographyService.decrypt(validPrivateKeyBase64, encryptedValueBase64);

        assertThat(decryptedBytes, equalTo(SOME_DECRYPTED_VALUE));
    }

    @Test(expected = Exception.class)
    public void shouldNotDecryptValueWhenKeysAreDifferent() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RsaAlgorithm.DEFAULT.getJceName());
        keyGen.initialize(2048);

        KeyPair encryptionKeyPair = keyGen.generateKeyPair();
        String encryptionPublicKeyBase64 = Base64.getEncoder().encodeToString(
            encryptionKeyPair.getPublic().getEncoded());

        KeyPair decryptionKeyPair = keyGen.generateKeyPair();
        String decryptionPrivateKeyBase64 = Base64.getEncoder().encodeToString(
            decryptionKeyPair.getPrivate().getEncoded());
        byte[] encryptedBytes = asymmetricCryptographyService.encrypt(encryptionPublicKeyBase64, SOME_DECRYPTED_VALUE);

        asymmetricCryptographyService.decrypt(decryptionPrivateKeyBase64, encryptedBytes);
    }

    @Test(expected = Exception.class)
    public void shouldThrowExceptionWhenEcryptWithKeyPairGeneratedWithUnexpectedAlgorithm() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);

        KeyPair invalidKeyPair = keyGen.generateKeyPair();
        String publicKeyBase64 = Base64.getEncoder().encodeToString(invalidKeyPair.getPublic().getEncoded());

        asymmetricCryptographyService.encrypt(publicKeyBase64, SOME_DECRYPTED_VALUE);
    }

    @Test(expected = Exception.class)
    public void shouldThrowExceptionWhenDecryptWithKeyPairGeneratedWithUnexpectedAlgorithm() throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048);

        KeyPair invalidKeyPair = keyGen.generateKeyPair();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(invalidKeyPair.getPrivate().getEncoded());

        asymmetricCryptographyService.decrypt(privateKeyBase64, SOME_ENCRYPTED_VALUE);
    }
}
