package com.security.cryptograph.service;

import com.security.cryptograph.domain.Country;
import lombok.SneakyThrows;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doThrow;


@RunWith(MockitoJUnitRunner.class)
public class AesCryptoServiceTest {

    private static final String PASS_ORIGINAL = "123456";
    private static final String SECRET = "c0VjUmVUa0VZckVubkVyT1JiSVRvRW5jcllwVERlY1J5UFRjMFZqVW1WVWEwVlpja1Z1YmtWeVQxSmlTVlJ2Ulc1amNsbHdWRVJsWTFKNVVGUT0=";
    private String encryptPass;
    private String decryptPass;

    @InjectMocks
    private AesCryptoService aesCryptoService;

    @Test
    public void shouldEncryptAndDecryptTextCorrectly() throws Exception {
        encryptPass = aesCryptoService.encrypt(SECRET, PASS_ORIGINAL);
        decryptPass = aesCryptoService.decrypt(SECRET, encryptPass);
        assertEquals(PASS_ORIGINAL, decryptPass);
    }

    @Test
    public void shouldEncryptAndDecryptModeKeySizeIterationTextCorrectly() throws Exception {
        aesCryptoService = new AesCryptoService(128,1989);
        encryptPass = aesCryptoService.encrypt(SECRET, PASS_ORIGINAL);
        decryptPass = aesCryptoService.decrypt(SECRET, encryptPass);
        assertEquals(PASS_ORIGINAL, decryptPass);
    }

    @Test(expected = Exception.class)
    public void shouldExceptionOnDecryptSecretInvalid() throws Exception {
        final String SECRET_INVALID = "33c0VjUmVUa0VZckVubkVyT1JiSVRvRW5jcllwVERlVVGUT0=";
        encryptPass = aesCryptoService.decrypt(SECRET, PASS_ORIGINAL);
        doThrow(Exception.class).when(aesCryptoService).decrypt(SECRET_INVALID, PASS_ORIGINAL);
    }

}
