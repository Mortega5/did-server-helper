package org.fiware.did.server.helper;

import io.micronaut.runtime.Micronaut;

/**
 * Main class to bootstrap the Micronaut application.
 *
 * The configuration for the JWKS key and the exposure of the endpoint
 * are handled automatically by the Micronaut Security module
 * and the application.yml configuration file.
 */
public class Application {

    public static void main(String[] args) {
        Micronaut.run(Application.class, args);
    }
}
