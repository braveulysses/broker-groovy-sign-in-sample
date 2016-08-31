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

import java.util.stream.Collectors

/**
 * The login handler. This class is responsible for creating a {@link State}
 * object and an OpenID Connect authentication request. It also redirects the
 * user-agent to the authentication server.
 *
 * The login endpoint takes the following query parameters:
 * <ul>
 *   <li>return_uri - The application URI to return to after receiving a
 *   successful authentication response.</li>
 *   <li>scope - The scopes to request.</li>
 *   <li>acr_values - A list, in order of preference, of ACRs, any one of which
 *   the application expects to be satisfied by the authentication request.</li>
 *   <li>prompt - Login and consent directives that may influence the
 *   authentication server's behavior.</li>
 * </ul>
 *
 * The login endpoint may use the following inputs from the {@link AppSession}:
 * <ul>
 *   <li>required_scope - Any scopes that must be granted for the
 *   authentication request to be considered successful. This set is put into
 *   the state and is enforced by the application after the authentication
 *   response is received.</li>
 *   <li>required_acr_values - A set of ACRs, any one of which must have been
 *   satisfied for the authentication request to be considered successful. This
 *   set is put into the state and is enforced by the application after the
 *   authentication response is received.</li>
 * </ul>
 */
@Slf4j
class LoginHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    String returnUri = ctx.getRequest().getQueryParams().get("return_uri")
    Set<String> requestedScopes = ctx.getRequest().getQueryParams()
            .get("scope")?.split(' ') as Set
    List<String> acrs = ctx.getRequest().getQueryParams()
            .get("acr_values")?.split(' ') as List
    String prompt = ctx.getRequest().getQueryParams().get("prompt")

    AppConfig config = ctx.get(AppConfig)
    AppSession.fromContext(ctx).then { AppSession appSession ->
      Set<String> requiredScopes = appSession.getRequiredScopes()
      Set<String> requiredAcrs = appSession.getRequiredAcrs()
      State state = new State(appSession.getSessionSecret(),
                              config.getClientId(), returnUri,
                              requiredScopes, requiredAcrs)
      JWSObject stateJws = state.sign(config.getSigningKey())
      String stateJwt = stateJws.serialize()
      appSession.setState(stateJwt)
      appSession.updateNonce()
      appSession.setRequiredScopes(null)
      appSession.setRequiredAcrs(null)
      Session session = ctx.get(Session)
      session.set("s", appSession).onError {
        throw new SessionException("Failed to update session")
      }.then {
        URI authUri = authenticationURI(appSession, config,
                                        requestedScopes, acrs, prompt)
        log.info("Redirecting to authentication URI '{}'", authUri.toString())
        ctx.redirect authUri
      }
    }
  }

  private static URI authenticationURI(AppSession appSession, AppConfig config,
                                       Set<String> scopes, List<String> acrs,
                                       String prompt) {
    Map<String, String> params = [
            response_type: "code",
            state: appSession.getState(),
            nonce: appSession.getNonce(),
            client_id: config.getClientId(),
            redirect_uri: config.getRedirectUri()
    ]
    if (scopes && !scopes.isEmpty()) {
      String scope = scopes.stream().collect(Collectors.joining(' '))
      params.put("scope", scope)
    }
    if (acrs && !acrs.isEmpty()) {
      String acrValues = acrs.stream().collect(Collectors.joining(' '))
      params.put("acr_values", acrValues)
    }
    if (prompt) {
      params.put("prompt", prompt)
    }

    return HttpUrlBuilder.base(new URI(config.getAuthorizeEndpoint()))
            .params(params)
            .build()
  }
}
