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
import com.example.app.models.TokenRequest
import com.example.app.models.TokenResponse
import com.example.app.util.HttpsUtil
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import com.unboundid.scim2.common.utils.JsonUtils
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.http.MediaType
import ratpack.http.client.HttpClient
import ratpack.session.Session
import ratpack.util.MultiValueMap

/**
 * Handles OpenID Connect redirect responses. If an authorization code is
 * received from the authentication server, then it is exchanged for an access
 * token and ID token, and the user's session is marked as authenticated.
 */
@Slf4j
class CallbackHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    AppConfig config = ctx.get(AppConfig)
    MultiValueMap<String, String> queryParams = ctx.getRequest().getQueryParams()

    if (queryParams.error) {
      // Handle error response.
      log.warn("Received error callback URI {}", ctx.getRequest().getUri())
      String exceptionMessage =
              "Authentication error! error=${queryParams.error}; " +
                      "error_description=${queryParams.error_description}"
      throw new RuntimeException(exceptionMessage)
    } else {
      // Handle response with authorization code.
      AppSession.fromContext(ctx).then { AppSession appSession ->
        log.info("Received success callback URI {}", ctx.getRequest().getUri())
        String stateJwt = queryParams.state
        if (stateJwt) {
          if (stateJwt != appSession.getState()) {
            throw new RuntimeException("Received unexpected state from authentication server")
          }
          if (!State.verify(stateJwt, config.getSigningKey(), appSession.getSessionSecret())) {
            throw new RuntimeException("state verification failed")
          }
        } else {
          throw new RuntimeException("state parameter not found")
        }
        String authorizationCode = queryParams.code
        if (authorizationCode) {
          // Make a token request using the authorization code.
          log.info("Requesting access token")
          requestToken(ctx, config, appSession, authorizationCode)
        } else {
          throw new RuntimeException("code parameter not found")
        }
      }
    }
  }

  private static void requestToken(Context ctx, AppConfig config,
                                   AppSession appSession, String authorizationCode) {
    TokenRequest tokenRequest = new TokenRequest(
            code: authorizationCode,
            redirectURI: new URI(config.getRedirectUri())
    )
    HttpClient httpClient = ctx.get(HttpClient)
    httpClient.post(new URI(config.getTokenEndpoint())) { requestSpec ->
      if (!config.isStrictHttpsValidation()) {
        requestSpec.sslContext(HttpsUtil.createInsecureSSLContext())
      }
      requestSpec.headers.add("Content-Type", MediaType.APPLICATION_FORM)
      requestSpec.headers.add("Accept", MediaType.APPLICATION_JSON)
      requestSpec.basicAuth(config.getClientId(), config.getClientSecret())
      requestSpec.body { body ->
        body.type(MediaType.APPLICATION_FORM).text(tokenRequest.formUrlEncoded())
      }
    }.onError { throwable ->
      throw new RuntimeException("Error while requesting token", throwable)
    }.map { response ->
      return response.getBody().getText()
    }.then { body ->
      log.info("Token response: ${body}")
      TokenResponse tokenResponse =
              JsonUtils.createObjectMapper().readValue(body, TokenResponse)
      validateTokenResponse(tokenResponse, config)
      appSession.setAuthenticated(true)
      appSession.setAccessToken(tokenResponse.getAccessToken())
      appSession.setIdToken(tokenResponse.getIdToken())
      Session session = ctx.get(Session)
      session.set("s", appSession).onError {
        throw new RuntimeException("Failed to update session")
      }.then {
        log.info("Verified token response")
        println appSession.getNonce()
        println appSession.getAuthenticated()

        ctx.redirect "/"
      }
    }
  }

  private static void validateTokenResponse(TokenResponse tokenResponse, AppConfig config) {
    log.info("Checking scopes in token response")
    if (!tokenResponse.getScopes().isEmpty()) {
      if (!tokenResponse.getScopes().containsAll(config.getScopes())) {
        throw new RuntimeException("Expected scopes not granted")
      }
    }

    log.info("Verifying access token")
    if (tokenResponse.getAccessToken()) {
      SignedJWT accessToken = SignedJWT.parse(tokenResponse.getAccessToken())
      String kid = accessToken.getHeader().getKeyID()
      JWK jwk = config.getJwks().getKeyByKeyId(kid)
      verifyJws(accessToken, jwk)
    } else {
      throw new RuntimeException("Access token missing from authentication response")
    }

    log.info("Verifying ID token")
    if (tokenResponse.getIdToken()) {
      SignedJWT idToken = SignedJWT.parse(tokenResponse.getIdToken())
      if (config.getIdTokenSigningAlgorithm().getName().startsWith("HS")) {
        verifyJws(idToken, config.getClientSecret())
      } else if (config.getIdTokenSigningAlgorithm().getName().startsWith("RS")) {
        String kid = idToken.getHeader().getKeyID()
        JWK jwk = config.getJwks().getKeyByKeyId(kid)
        verifyJws(idToken, jwk)
        // TODO: Further validate the ID token.
      } else {
        throw new RuntimeException("Unsupported JWA '${config.getIdTokenSigningAlgorithm().getName()}'")
      }
    }
  }

  private static void verifyJws(SignedJWT jwt, JWK jwk) {
    log.info("JWK: ${jwk.toJSONString()}")
    JWSVerifier verifier = new RSASSAVerifier((RSAKey) jwk)
    verifyJws(jwt, verifier)
  }

  private static void verifyJws(SignedJWT jwt, String sharedSecret) {
    JWSVerifier verifier = new MACVerifier(sharedSecret)
    verifyJws(jwt, verifier)
  }

  private static void verifyJws(SignedJWT jwt, JWSVerifier verifier) {
    if (!jwt.verify(verifier)) {
      throw new RuntimeException("Token signature could not be verified")
    }
  }
}
