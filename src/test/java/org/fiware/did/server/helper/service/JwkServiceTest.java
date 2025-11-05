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
package org.fiware.did.server.helper.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.fiware.did.server.helper.config.JwkConfiguration;
import org.fiware.did.server.helper.utils.KeyHelper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JwkServiceTest {

  private static Stream<Arguments> keyProvider() {
    return Stream.of(
        Arguments.of("RSA", 2048, null, "kid-rsa", "RS256"),
        Arguments.of("EC", null, "secp256r1", "kid-ec", "ES256"));
  }

  @ParameterizedTest
  @MethodSource("keyProvider")
  void generateKeyStoreAndLoadJwk(
      String type, Integer rsaSize, String ecCurve, String expectedKid, String expectedAlg)
      throws Exception {
    Path tmpDir = Files.createTempDirectory(Path.of("/tmp"), "jwk-test-");
    Path keyPath = tmpDir.resolve("key.pem");

    try {
      KeyPair kp;
      if ("EC".equalsIgnoreCase(type)) {
        kp = KeyHelper.generateEcKeyPair(ecCurve == null ? "secp256r1" : ecCurve);
      } else {
        kp = KeyHelper.generateRsaKeyPair(rsaSize == null ? 2048 : rsaSize);
      }

      KeyHelper.writePrivateKeyPem(kp.getPrivate(), keyPath);
      assertTrue(Files.exists(keyPath), "Private key file should exist in /tmp");

      JwkConfiguration config = new JwkConfiguration();
      config.setPrivateKeyPath(keyPath.toString());
      config.setKeyId(expectedKid);
      config.setAlgorithm(expectedAlg);

      JwkService service = new JwkService(config);
      Map<String, Object> jwksMap = service.getJwksMap();
      assertNotNull(jwksMap, "jwksMap should not be null");
      assertTrue(jwksMap.containsKey("keys"), "jwksMap should contain 'keys'");

      @SuppressWarnings("unchecked")
      List<Map<String, Object>> keys = (List<Map<String, Object>>) jwksMap.get("keys");
      assertEquals(1, keys.size(), "There should be exactly one key");

      Map<String, Object> keyJson = keys.get(0);
      assertEquals(expectedKid, keyJson.get("kid"));
      assertEquals(expectedAlg, keyJson.get("alg"));
      assertEquals("sig", keyJson.get("use"));
      assertEquals(type.toUpperCase(), keyJson.get("kty"));
    } finally {
      try (Stream<Path> files = Files.walk(tmpDir)) {
        files.forEach(
            p -> {
              try {
                Files.deleteIfExists(p);
              } catch (Exception ignored) {
              }
            });
      } catch (Exception ignored) {
      }
    }
  }
}
