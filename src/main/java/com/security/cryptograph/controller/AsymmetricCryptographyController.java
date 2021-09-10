package com.security.cryptograph.controller;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

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
@RequestMapping("/cripto")
@RequiredArgsConstructor
@Slf4j
public class AsymmetricCryptographyController {

    private final AsymmetricCryptographyService service;

    @Value("${security.public-key-base64}")
    private String publicKeyStaticBase64;

    @Value("${security.private-key-base64}")
    private String privateKeyStaticBase64;

    @GetMapping("/asym-dynamic/{valor}")
    public ResponseEntity<String> asymDynamicKeyPair(@PathVariable("valor") String valor) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RsaAlgorithm.DEFAULT.getJceName());
        keyGen.initialize(2048);

        KeyPair validKeyPair = keyGen.generateKeyPair();
        String validPublicKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPublic().getEncoded());
        String validPrivateKeyBase64 = Base64.getEncoder().encodeToString(validKeyPair.getPrivate().getEncoded());

        byte[] encryptedBytes = service.encrypt(validPublicKeyBase64, valor.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedBytes = service.decrypt(validPrivateKeyBase64, encryptedBytes);

        log.info("Valor original -> {}", valor);
        log.info("Valor encriptado -> {}", new String(encryptedBytes));
        log.info("Valor decriptado -> {}", new String(decryptedBytes));

        return ResponseEntity.ok(new String(decryptedBytes));
    }

    @GetMapping("/asym-static/{valor}")
    public ResponseEntity<String> asymStaticKeyPair(@PathVariable("valor") String valor) throws Exception {
        byte[] encryptedBytes = service.encrypt(publicKeyStaticBase64, valor.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedBytes = service.decrypt(privateKeyStaticBase64, encryptedBytes);

        log.info("Valor original -> {}", valor);
        log.info("Valor encriptado -> {}", new String(encryptedBytes));
        log.info("Valor decriptado -> {}", new String(decryptedBytes));

        return ResponseEntity.ok(new String(decryptedBytes));
    }

}
