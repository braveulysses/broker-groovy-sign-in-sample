/*
 * Copyright 2016 UnboundID Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.app.handlers

import com.example.app.models.AppConfig
import com.example.app.models.AppSession
import com.example.app.models.State
import com.nimbusds.jose.JWSObject
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.http.HttpUrlBuilder
import ratpack.session.Session

import java.util.stream.Collectors

/**
 * The login handler. This creates an OpenID Connect authentication request
 * and redirects the user-agent to the authentication server.
 */
@Slf4j
class LoginHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    AppConfig config = ctx.get(AppConfig)
    AppSession.fromContext(ctx).then { AppSession appSession ->
      State state = new State(appSession.getSessionSecret(), config.getClientId())
      JWSObject stateJws = state.sign(config.getSigningKey())
      String stateJwt = stateJws.serialize()
      appSession.setState(stateJwt)
      appSession.updateNonce()
      Session session = ctx.get(Session)
      session.set("s", appSession).onError {
        throw new RuntimeException("Failed to update session")
      }.then {
        URI authUri = authenticationURI(appSession, config)
        log.info("Redirecting to authentication URI '{}'", authUri.toString())
        ctx.redirect authUri
      }
    }
  }

  private static URI authenticationURI(AppSession appSession, AppConfig config) {
    Map<String, String> params = new HashMap<>()
    params.put("response_type", "code")
    params.put("state", appSession.getState())
    params.put("nonce", appSession.getNonce())
    params.put("client_id", config.getClientId())
    params.put("redirect_uri", config.getRedirectUri())
    if (!config.getScopes().isEmpty()) {
      String scopes =
              config.getScopes().stream().collect(Collectors.joining(' '))
      params.put("scope", scopes)
    }
    if (!config.getAcrValues().isEmpty()) {
      String acrValues =
              config.getAcrValues().stream().collect(Collectors.joining(' '))
      params.put("acr_values", acrValues)
    }

    return HttpUrlBuilder.base(new URI(config.getAuthorizeEndpoint()))
            .params(params)
            .build()
  }
}
