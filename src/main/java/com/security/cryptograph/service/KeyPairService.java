package com.security.cryptograph.service;

import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@Service
public class KeyPairService {

    public static final String KEY_ALGORITHM = "RSA";

    private static final int KEY_LENGTH = 2048;

    @SneakyThrows
    public KeyPair generateKeyPair() {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);

        keyGen.initialize(KEY_LENGTH);
        return keyGen.generateKeyPair();
    }
}
