package org.fiware.did.server.helper.config;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.NonNull;

@ConfigurationProperties("jwks")
public class JwkConfiguration {

    @NonNull
    private String keyId;

    @NonNull
    private String algorithm;

    @NonNull
    private String privateKeyPath;

    // Getters y Setters
    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }
}