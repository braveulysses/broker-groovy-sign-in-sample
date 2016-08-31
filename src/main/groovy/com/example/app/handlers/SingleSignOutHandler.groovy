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

import com.example.app.exceptions.SessionException
import com.example.app.models.AppConfig
import com.example.app.models.AppSession
import com.example.app.models.State
import com.nimbusds.jose.JWSObject
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.http.HttpUrlBuilder
import ratpack.session.Session

/**
 * Performs a single sign out by invoking the authentication server's logout
 * endpoint.
 */
@Slf4j
class SingleSignOutHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    AppConfig config = ctx.get(AppConfig)
    String returnUri = config.getRedirectUri()
    log.info("returnUri: ${returnUri}")
    AppSession.fromContext(ctx).then { AppSession appSession ->
      log.info("Logging out of application")
      State state = new State(appSession.getSessionSecret(),
                              config.getClientId(), returnUri)
      JWSObject stateJws = state.sign(config.getSigningKey())
      String stateJwt = stateJws.serialize()
      appSession.setState(stateJwt)
      appSession.updateNonce()
      appSession.setRequiredScopes(null)
      appSession.setAcceptableAcrs(null)
      appSession.setAuthenticated(false)
      appSession.setAccessToken(null)
      appSession.setIdToken(null)
      Session session = ctx.get(Session)
      session.set("s", appSession).onError {
        throw new SessionException("Failed to update session")
      }.then {
        log.info("Logging out of authentication server")
        URI singleSignoutUri =
                HttpUrlBuilder.base(new URI(config.getLogoutEndpoint()))
                        .params([ post_logout_redirect_uri: returnUri,
                                  state: stateJwt ] as Map)
                        .build()
        ctx.redirect singleSignoutUri
      }
    }
  }
}
