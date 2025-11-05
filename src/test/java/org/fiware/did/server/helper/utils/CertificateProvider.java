package org.fiware.did.server.helper.utils;

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.test.support.TestPropertyProvider;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;

@MicronautTest
public class CertificateProvider {

    private static Path tmpDir;

    @BeforeAll
    public static void createCerts() {
        try {
            tmpDir = Files.createDirectory(Path.of("/tmp/jwk-it"));
            Path privateKeyPath = tmpDir.resolve("key.pem");
            Path certPath = tmpDir.resolve("cert.pem");

            KeyHelper.generateAndStoreKey(
                    "RSA",
                    privateKeyPath,
                    certPath,
                    2048,
                    null,
                    "CN=it-test",
                    365
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @AfterAll
    public static void cleanup() {

        if (tmpDir != null) {
            try(Stream<Path> files = Files.walk(tmpDir)){
                files.forEach(p -> {
                    try { Files.deleteIfExists(p); } catch (Exception ignored) {}
                });
            } catch (Exception ignored) { }
            try {
                Files.deleteIfExists(tmpDir);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
