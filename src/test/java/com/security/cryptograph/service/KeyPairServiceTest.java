package com.security.cryptograph.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;

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
        assertEquals(keyPair.getPublic().getAlgorithm(), ALGORITHM);
        assertEquals(keyPair.getPrivate().getAlgorithm(), ALGORITHM);
    }
}
