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
package com.example.app.models

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import ratpack.http.HttpUrlBuilder

/**
 * The application configuration model. The default values defined here may be
 * overridden by the config.yaml configuration file.
 */
@SuppressWarnings("GroovyUnusedDeclaration")
class AppConfig {
  // If false, any HTTP clients used by this application will use blind trust
  // and perform no hostname verification when making HTTPS connections.
  boolean strictHttpsValidation = true
  // A secret key that the application uses to sign the state parameter value
  // of authentication requests. The application will generate this secret
  // automatically upon startup.
  String signingKey

  // The expected value of the authentication server's iss claim.
  String issuer = "https://example.com"

  // The authentication server's base URI.
  String authenticationServerBaseUri = "https://example.com/"
  // The resource server's base URI.
  String resourceServerBaseUri = "https://example.com/"

  // The authentication server's account management application.
  String accountManagerUri

  // The signing algorithm that the authentication server is expected to use
  // to sign ID tokens.
  JWSAlgorithm idTokenSigningAlgorithm = JWSAlgorithm.RS256
  // How often to retrieve keys from the authentication server's JWKS endpoint.
  int jwksFetchInterval = 5 * 60
  // The JWK set retrieved from the authentication server. The application will
  // set this automatically.
  JWKSet jwks

  // The application's client ID.
  String clientId
  // The application's client secret.
  String clientSecret
  // The application's OpenID Connect redirect URI.
  String redirectUri = "http://localhost:5050/callback"

  public URI getAuthorizeEndpoint() {
    return HttpUrlBuilder.base(new URI(authenticationServerBaseUri))
            .path("oauth/authorize").build()
  }

  public URI getTokenEndpoint() {
    return HttpUrlBuilder.base(new URI(authenticationServerBaseUri))
            .path("oauth/token").build()
  }

  public URI getRevokeEndpoint() {
    return HttpUrlBuilder.base(new URI(authenticationServerBaseUri))
            .path("oauth/revoke").build()
  }

  public URI getLogoutEndpoint() {
    return HttpUrlBuilder.base(new URI(authenticationServerBaseUri))
            .path("oauth/logout").build()
  }

  public URI getAccountManagerUri() {
    return new URI(accountManagerUri)
  }

  public URI getJwksEndpoint() {
    return HttpUrlBuilder.base(new URI(authenticationServerBaseUri))
            .path("jwks").build()
  }

  public URI getScimEndpoint() {
    return new URI(resourceServerBaseUri)
  }

  public void setIdTokenSigningAlgorithm(String idTokenSigningAlgorithm) {
    this.idTokenSigningAlgorithm = JWSAlgorithm.parse(idTokenSigningAlgorithm)
  }
}
