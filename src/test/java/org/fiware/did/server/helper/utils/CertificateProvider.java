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
package org.fiware.did.server.helper.utils;

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

@MicronautTest
public class CertificateProvider {

  private static Path tmpDir;

  @BeforeAll
  public static void createCerts() {
    try {
      tmpDir = Files.createDirectory(Path.of("/tmp/jwk-it"));
      Path privateKeyPath = tmpDir.resolve("key.pem");
      Path certPath = tmpDir.resolve("cert.pem");

      KeyHelper.generateAndStoreKey("RSA", privateKeyPath, certPath, 2048, null, "CN=it-test", 365);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @AfterAll
  public static void cleanup() {

    if (tmpDir != null) {
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
      try {
        Files.deleteIfExists(tmpDir);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
