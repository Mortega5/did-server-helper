package org.fiware.did.server.helper.controller;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import org.fiware.did.server.helper.service.JwkService;

import java.util.Map;

@Controller("/.well-known")
public class JwkController {

    private final JwkService jwkService;

    public JwkController(JwkService jwkService) {
        this.jwkService = jwkService;
    }

    @Get(uri = "/jwks", produces = MediaType.APPLICATION_JSON)
    public Map<String, Object> getJwkSet() {
        return jwkService.getJwksMap();
    }
}