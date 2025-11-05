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

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import java.util.Map;
import org.fiware.did.server.helper.service.JwkService;

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
