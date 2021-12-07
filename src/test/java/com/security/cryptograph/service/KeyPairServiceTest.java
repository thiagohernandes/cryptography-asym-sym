package com.security.cryptograph.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.util.Base64;

import org.junit.Before;
import org.junit.Test;

public class KeyPairServiceTest {

    private static final String ALGORITHM = "RSA";

    private KeyPairService keyPairService;

    @Before
    public void setUp() {
        this.keyPairService = new KeyPairService();
    }

    @Test
    public void shouldGenerateKeyPair() throws Exception {
        KeyPair keyPair = keyPairService.generateKeyPair();
        assertNotNull(keyPair);
        assertEquals(ALGORITHM, keyPair.getPublic().getAlgorithm());
        assertEquals(ALGORITHM, keyPair.getPrivate().getAlgorithm());
        String validPublicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String validPrivateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        assertNotNull(validPublicKeyBase64);
        assertNotNull(validPrivateKeyBase64);
    }
}
