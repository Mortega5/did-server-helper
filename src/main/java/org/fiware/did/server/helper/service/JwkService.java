package org.fiware.did.server.helper.service;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.inject.Singleton;
import org.fiware.did.server.helper.config.JwkConfiguration;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@Singleton
public class JwkService {

    private static final String KID_KEY = "kid";
    private static final String ALG_KEY = "alg";
    private static final String USE_KEY = "use";

    private final Map<String, Object> jwksMap;

    public JwkService(JwkConfiguration config) {

        String keyPath = config.getPrivateKeyPath();
        String keyId = config.getKeyId();
        String algorithm = config.getAlgorithm();

        JWK jwk = loadKey(keyPath, keyId, algorithm);

        JWKSet jwkSet = new JWKSet(jwk.toPublicJWK());
        this.jwksMap = jwkSet.toJSONObject();
    }

    private JWK loadKey(String path, String kid, String algorithm) {
        try {
            String pemContent = Files.readString(Path.of(path));
            JWK jwk = JWK.parseFromPEMEncodedObjects(pemContent);

            Map<String, Object> jwkJson = jwk.toJSONObject();

            jwkJson.put(KID_KEY, kid);
            jwkJson.put(ALG_KEY, algorithm);
            jwkJson.put(USE_KEY, "sig");

            return JWK.parse(jwkJson);

        } catch (Exception e) {
            throw new RuntimeException("Failed to load or parse private key from path: " + path, e);
        }
    }

    public Map<String, Object> getJwksMap() {
        return this.jwksMap;
    }
}