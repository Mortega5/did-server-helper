package org.fiware.did.server.helper.controller;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.fiware.did.server.helper.utils.CertificateProvider;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest(environments = {"it"})
class JwkControllerIT extends CertificateProvider {

    @Inject
    @Client("/")
    private HttpClient client;

    @Test
    void shouldLoadJwkFromGeneratedFiles() {

        @SuppressWarnings("unchecked")
        Map<String, Object> jwksMap = client.toBlocking().retrieve(HttpRequest.GET("/.well-known/jwks"), Map.class);

        assertNotNull(jwksMap, "jwksMap should not be null");
        assertTrue(jwksMap.containsKey("keys"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwksMap.get("keys");
        assertEquals(1, keys.size(), "There should be exactly one key");

        Map<String, Object> key = keys.get(0);
        assertEquals("did-server-key-01", key.get("kid"));
        assertEquals("RS256", key.get("alg"));
        assertEquals("sig", key.get("use"));
        assertEquals("RSA", key.get("kty"));
    }
}
