package com.security.cryptograph.controller;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.rsa.crypto.RsaAlgorithm;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.cryptograph.service.AsymmetricCryptographyService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/crypto")
@RequiredArgsConstructor
@Slf4j
public class AsymmetricCryptographyController {

    private final AsymmetricCryptographyService service;

    @Value("${security.public-key-base64}")
    private String publicKeyStaticBase64;

    @Value("${security.private-key-base64}")
    private String privateKeyStaticBase64;

    @GetMapping("/dynamic/{text}")
    public ResponseEntity<String> asymDynamicKeyPair(@PathVariable("text") String text) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RsaAlgorithm.DEFAULT.getJceName());
        keyGen.initialize(2048);

        KeyPair validKeyPair = keyGen.generateKeyPair();
        String validPublicKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPublic().getEncoded());
        String validPrivateKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPrivate().getEncoded());

        byte[] encryptedBytes = service.encrypt(validPublicKeyBase64, text.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedBytes = service.decrypt(validPrivateKeyBase64, encryptedBytes);

        makeMsgValue(text, encryptedBytes, decryptedBytes);

        return ResponseEntity.ok(new String(decryptedBytes));
    }

    @GetMapping("/static/{text}")
    public ResponseEntity<String> asymStaticKeyPair(@PathVariable("text") String text) throws Exception {

        byte[] encryptedBytes = service.encrypt(publicKeyStaticBase64, text.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedBytes = service.decrypt(privateKeyStaticBase64, encryptedBytes);

        makeMsgValue(text, encryptedBytes, decryptedBytes);

        return ResponseEntity.ok(new String(decryptedBytes));
    }

    private void makeMsgValue(String text, byte[] encryptedBytes, byte[] decryptedBytes) {
        log.info("Original value -> {}", text);
        log.info("Value encrypted -> {}", new String(encryptedBytes));
        log.info("Value decrypted -> {}", new String(decryptedBytes));
    }

}
