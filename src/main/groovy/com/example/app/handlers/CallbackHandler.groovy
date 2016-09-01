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

import com.example.app.exceptions.CallbackErrorException
import com.example.app.exceptions.CallbackValidationException
import com.example.app.exceptions.TokenRequestException
import com.example.app.models.AppConfig
import com.example.app.models.AppSession
import com.example.app.models.State
import com.example.app.models.TokenRequest
import com.example.app.models.TokenResponse
import com.example.app.util.HttpsUtil
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import com.unboundid.scim2.common.utils.JsonUtils
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.http.MediaType
import ratpack.http.client.HttpClient
import ratpack.util.MultiValueMap

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import static com.example.app.util.TokenUtil.verifyJws

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
              "Authentication error: error=${queryParams.error}; " +
                      "error_description=${queryParams.error_description}"
      throw new CallbackErrorException(
              exceptionMessage, queryParams.error, queryParams.error_description)
    } else {
      // Handle response with authorization code.
      AppSession.fromContext(ctx).then { AppSession appSession ->
        log.info("Received success callback URI {}", ctx.getRequest().getUri())

        String stateJwt = queryParams.state
        if (stateJwt) {
          if (stateJwt != appSession.getState()) {
            throw new CallbackValidationException(
                    "Received unexpected state from authentication server")
          }
          if (!State.verify(stateJwt, config.getSigningKey(),
                            appSession.getSessionSecret())) {
            throw new CallbackValidationException("state verification failed")
          }
        } else {
          throw new CallbackValidationException("state parameter not found")
        }

        String authorizationCode = queryParams.code
        if (authorizationCode) {
          // Make a token request using the authorization code.
          log.info("Requesting access token")
          requestToken(ctx, config, appSession, authorizationCode)
          // Redirect the user-agent to the URI specified in the return_uri
          // when the login request was made earlier.
          String returnUri = SignedJWT.parse(stateJwt).getJWTClaimsSet()
                  .getClaim("return_uri")
          if (returnUri) {
            ctx.redirect returnUri
          } else {
            ctx.redirect "/"
          }
        } else {
          // If the state parameter is present but the code parameter is not,
          // then this might be a logout redirect. In that case, just redirect
          // to the root path.
          ctx.redirect "/"
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
      throw new TokenRequestException("Error while requesting token", throwable)
    }.map { response ->
      return response.getBody().getText()
    }.then { body ->
      log.info("Token response: ${body}")
      TokenResponse tokenResponse =
              JsonUtils.createObjectMapper().readValue(body, TokenResponse)
      validateTokenResponse(tokenResponse, config, appSession)
      appSession.setAuthenticated(true)
      appSession.setAccessToken(tokenResponse.getAccessToken())
      appSession.setIdToken(tokenResponse.getIdToken())
      appSession.save(ctx) {
        log.info("Verified token response")
      }
    }
  }

  private static void validateTokenResponse(
          TokenResponse tokenResponse, AppConfig config, AppSession appSession) {
    log.info("Checking for expected scopes in token response")
    if (!tokenResponse.getScopes().isEmpty()) {
      // Get the expected scopes from the app session.
      Set<String> requiredScopes = appSession.getRequiredScopes()
      if (requiredScopes && !requiredScopes.isEmpty()) {
        if (!tokenResponse.getScopes().containsAll(requiredScopes)) {
          throw new CallbackValidationException(
                  "Expected scopes not granted. " +
                          "Expected scopes: ${requiredScopes}; " +
                          "Actual scopes: ${tokenResponse.getScopes()}")
        }
      }
    }

    log.info("Verifying access token")
    if (!tokenResponse.getAccessToken()) {
      throw new CallbackValidationException(
              "Access token missing from authentication response")
    }

    log.info("Verifying ID token")
    if (tokenResponse.getIdToken()) {
      validateIdToken(tokenResponse.getIdToken(), tokenResponse.getAccessToken(),
                      config, appSession)
    } else {
      throw new CallbackValidationException(
              "ID token missing from authentication response")
    }
  }

  private static void validateIdToken(String idToken, String accessToken,
                                      AppConfig config, AppSession appSession) {
    // See OpenID Connect Core, 3.1.3.7, ID Token Validation.

    // 6. If the ID Token is received via direct communication between the
    // Client and the Token Endpoint (which it is in this flow), the TLS server
    // validation MAY be used to validate the issuer in place of checking the
    // token signature. The Client MUST validate the signature of all other ID
    // Tokens according to JWS using the algorithm specified in the JWT alg
    // Header Parameter. The Client MUST use the keys provided by the Issuer.
    // 8. If the JWT alg Header Parameter uses a MAC based algorithm such as
    // HS256, HS384, or HS512, the octets of the UTF-8 representation of the
    // client_secret corresponding to the client_id contained in the aud
    // (audience) Claim are used as the key to validate the signature. For MAC
    // based algorithms, the behavior is unspecified if the aud is multi-valued
    // or if an azp value is present that is different than the aud value.
    SignedJWT idTokenJws = SignedJWT.parse(idToken)
    if (config.getIdTokenSigningAlgorithm().getName().startsWith("HS")) {
      verifyJws(idTokenJws, config.getClientSecret())
    } else if (config.getIdTokenSigningAlgorithm().getName().startsWith("RS")) {
      String kid = idTokenJws.getHeader().getKeyID()
      JWK jwk = config.getJwks().getKeyByKeyId(kid)
      verifyJws(idTokenJws, jwk)
    } else {
      throw new CallbackValidationException(
              "Unsupported JWA '${config.getIdTokenSigningAlgorithm().getName()}'")
    }

    // 2. The Issuer Identifier for the OpenID Provider (which is typically
    // obtained during Discovery) MUST exactly match the value of the iss
    // (issuer) Claim.
    if (idTokenJws.getJWTClaimsSet().getIssuer() != config.getIssuer()) {
      throw new CallbackValidationException(
              "Expected iss '${config.getIssuer()}' but was " +
                      "'${idTokenJws.getJWTClaimsSet().getIssuer()}'")
    }
    matchClaims("iss", idTokenJws.getJWTClaimsSet().getIssuer(),
                config.getIssuer())

    // 3. The Client MUST validate that the aud (audience) Claim contains its
    // client_id value registered at the Issuer identified by the iss (issuer)
    // Claim as an audience. The aud (audience) Claim MAY contain an array with
    // more than one element. The ID Token MUST be rejected if the ID Token
    // does not list the Client as a valid audience, or if it contains
    // additional audiences not trusted by the Client.
    if (idTokenJws.getJWTClaimsSet().getAudience().size() != 1) {
      throw new CallbackValidationException(
              "Expected aud claim to contain exactly one value")
    }
    matchClaims("aud", idTokenJws.getJWTClaimsSet().getAudience().first(),
                config.getClientId())

    // 9. The current time MUST be before the time represented by the exp Claim.
    if (idTokenJws.getJWTClaimsSet().getExpirationTime().before(new Date())) {
      throw new CallbackValidationException(
              "Expected current time to not precede exp time")
    }

    // 11. If a nonce value was sent in the Authentication Request, a nonce
    // Claim MUST be present and its value checked to verify that it is the
    // same value as the one that was sent in the Authentication Request. The
    // Client SHOULD check the nonce value for replay attacks. The precise
    // method for detecting replay attacks is Client specific.
    matchClaims("nonce", idTokenJws.getJWTClaimsSet().getClaim("nonce") as String,
                appSession.getNonce())

    // To validate an Access Token issued from the Token Endpoint with an
    // ID Token, the Client SHOULD do the following:
    // 1. Hash the octets of the ASCII representation of the access_token with
    // the hash algorithm specified in JWA for the alg Header Parameter of the
    // ID Token's JOSE Header. For instance, if the alg is RS256, the hash
    // algorithm used is SHA-256.
    // 2. Take the left-most half of the hash and base64url encode it.
    // 3. The value of at_hash in the ID Token MUST match the value produced
    // in the previous step.
    validateAccessTokenHash(idTokenJws.getHeader().getAlgorithm(), accessToken,
                            idTokenJws.getJWTClaimsSet().getClaim("at_hash") as String)

    // If the resource handler that initiated the authentication request
    // requires a specific ACR, check here.
    if (appSession.getAcceptableAcrs() && appSession.getAcceptableAcrs() != null) {
      String actualAcr = idTokenJws.getJWTClaimsSet().getStringClaim("acr")
      if (actualAcr) {
        if (!appSession.getAcceptableAcrs().contains(actualAcr)) {
          throw new CallbackValidationException(
                  "ACR '${actualAcr}' is not an acceptable ACR")
        }
      }
    }
  }

  private static void matchClaims(String claimName,
                                  String expectedClaim, String actualClaim) {
    if (actualClaim != expectedClaim) {
      throw new CallbackValidationException(
              "Expected ${claimName} '${expectedClaim}' but was '${actualClaim}'")
    }
  }

  private static void validateAccessTokenHash(
          JWSAlgorithm signingAlgorithm, String accessToken, String atHash) {
    // This works as long as the hash algorithm is SHA-based, which is
    // apparently true for all JWAs.
    MessageDigest messageDigest = MessageDigest.getInstance(
            "SHA-" + signingAlgorithm.getName().substring(2))

    byte[] hash = messageDigest.digest(accessToken.getBytes(StandardCharsets.UTF_8))
    byte[] leftHalfHash = Arrays.copyOf(hash, (int) hash.length / 2)
    String expectedAtHash = Base64URL.encode(leftHalfHash)
    matchClaims("at_hash", expectedAtHash, atHash)
  }
}
