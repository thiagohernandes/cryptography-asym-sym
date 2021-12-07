package com.security.cryptograph.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import com.security.cryptograph.domain.Country;

import lombok.SneakyThrows;


@RunWith(MockitoJUnitRunner.class)
public class SymmetricCryptographyServiceTest {

    private static final String TEXT_INPUT = "text to encrypt";
    final Country country = Country.builder().name("USA").currency("dollar").build();
    final String algorithm = "AES/CBC/PKCS5Padding";

    SecretKey key;
    IvParameterSpec ivParameterSpec;

    private SymmetricCryptographyService symmetricCryptographyService;

    @Before
    @SneakyThrows
    public void setUp() {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        this.symmetricCryptographyService = new SymmetricCryptographyService(cipher);
        this.key = symmetricCryptographyService.generateKey(128);
        this.ivParameterSpec = symmetricCryptographyService.generateIv();
    }

    @Test
    public void shouldEncryptAndDecryptTextCorrectly() throws Exception {
        SecretKey key = symmetricCryptographyService.generateKey(128);

        String cipherText = symmetricCryptographyService.encryptText(TEXT_INPUT, key, ivParameterSpec);
        String plainText = symmetricCryptographyService.decryptText(cipherText, key, ivParameterSpec);

        assertEquals(TEXT_INPUT, plainText);
    }

    @Test(expected = Exception.class)
    public void shouldExceptionOnEncryptText() throws Exception {
        symmetricCryptographyService.encryptText(TEXT_INPUT, null, ivParameterSpec);
    }

    @Test(expected = Exception.class)
    public void shouldExceptionOnDecryptText() throws Exception {
        String cipherText = symmetricCryptographyService.encryptText(TEXT_INPUT, key, ivParameterSpec);
        symmetricCryptographyService.decryptText(cipherText, null, ivParameterSpec);
    }

    @Test
    public void shouldEncryptAndDecryptObjectCorrectly() throws Exception {
        SealedObject sealedObject = symmetricCryptographyService.
            encryptObject(algorithm, country, key, ivParameterSpec);

        Country object = (Country) symmetricCryptographyService
            .decryptObject(algorithm, sealedObject, key, ivParameterSpec);

        assertThat(country).isEqualTo(object);
    }

    @Test(expected = Exception.class)
    public void shouldExceptionOnEncryptObject() throws Exception {
        symmetricCryptographyService.encryptObject(algorithm, country, null, ivParameterSpec);
    }

    @Test(expected = Exception.class)
    public void shouldExceptionOnDecryptObject() throws Exception {
        SealedObject sealedObject = symmetricCryptographyService.
            encryptObject(algorithm, country, key, ivParameterSpec);

        symmetricCryptographyService.decryptObject(algorithm, sealedObject, null, ivParameterSpec);
    }
}
