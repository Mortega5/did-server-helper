/**
* Copyright 2025 FIWARE
* <p>
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* <p>
* http://www.apache.org/licenses/LICENSE-2.0
* <p>
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.fiware.did.server.helper.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import org.fiware.did.server.helper.utils.CertificateProvider;
import org.junit.jupiter.api.Test;

@MicronautTest(environments = {"it"})
class JwkControllerIT extends CertificateProvider {

  @Inject
  @Client("/")
  private HttpClient client;

  @Test
  void shouldLoadJwkFromGeneratedFiles() {

    @SuppressWarnings("unchecked")
    Map<String, Object> jwksMap =
        client.toBlocking().retrieve(HttpRequest.GET("/.well-known/jwks"), Map.class);

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
