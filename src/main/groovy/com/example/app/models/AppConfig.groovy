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
  // The authentication server's OAuth 2 authorization endpoint.
  String authorizeEndpoint = "https://example.com/oauth/authorize"
  // The authentication server's OAuth 2 token endpoint.
  String tokenEndpoint = "https://example.com/oauth/token"
  // The authentication server's logout endpoint.
  String logoutEndpoint = "https://example.com/oauth/logout"
  // The authentication server's OpenID Connect JWKS endpoint.
  String jwksEndpoint = "https://example.com/jwks"
  // The authentication server's base SCIM 2 endpoint.
  String scimEndpoint = "https://example.com/scim/v2"

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

  public void setIdTokenSigningAlgorithm(String idTokenSigningAlgorithm) {
    this.idTokenSigningAlgorithm = JWSAlgorithm.parse(idTokenSigningAlgorithm)
  }
}
