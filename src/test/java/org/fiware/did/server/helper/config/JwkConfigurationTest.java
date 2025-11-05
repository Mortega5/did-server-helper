package org.fiware.did.server.helper.config;

import io.micronaut.context.annotation.ConfigurationProperties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class JwkConfigurationTest {

    @Test
    void testDefaultValuesAreNull() {
        JwkConfiguration config = new JwkConfiguration();
        assertNull(config.getKeyId(), "keyId should be null by default");
        assertNull(config.getAlgorithm(), "algorithm should be null by default");
        assertNull(config.getPrivateKeyPath(), "privateKeyPath should be null by default");
    }

    @Test
    void testGettersAndSetters() {
        JwkConfiguration config = new JwkConfiguration();

        config.setKeyId("my-key-id");
        config.setAlgorithm("RS256");
        config.setPrivateKeyPath("/path/to/key.pem");

        assertEquals("my-key-id", config.getKeyId());
        assertEquals("RS256", config.getAlgorithm());
        assertEquals("/path/to/key.pem", config.getPrivateKeyPath());
    }
}
