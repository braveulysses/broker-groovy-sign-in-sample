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
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT

import java.time.Duration
import java.time.Instant

/**
 * A user session state object that can be encoded into a JWT and signed. When
 * used in an OpenID Connect authentication request, the integrity of a state
 * object can be verified when it is returned in the authentication response.
 * Based on <a href="https://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-05">draft-bradley-oauth-jwt-encoded-state-05</a>,
 * "Encoding claims in the OAuth 2 state parameter using a JWT", by J. Bradley,
 * et al.
 */
class State {
  JWSAlgorithm jwa = JWSAlgorithm.HS256

  String rfp
  Date iat
  Date exp
  String aud

  public State(String sessionSecret, String clientId) {
    this.rfp = sessionSecret
    this.iat = new Date(Instant.now().toEpochMilli())
    this.exp = new Date((Instant.now() + Duration.ofMinutes(15)).toEpochMilli())
    this.aud = clientId
  }

  public JWSObject sign(String signingKey) {
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issueTime(iat)
            .expirationTime(exp)
            .audience(aud)
            .claim("rfp", rfp)
            .build()
    SignedJWT jwt = new SignedJWT(new JWSHeader(jwa), claimsSet)
    JWSSigner signer = new MACSigner(signingKey)
    jwt.sign(signer)
    return jwt
  }

  public static boolean verify(String jwt, String signingKey, String expectedRfp) {
    JWT parsedJwt = SignedJWT.parse(jwt)
    return verifyJws(jwt, signingKey) &&
            parsedJwt.getJWTClaimsSet().getClaim("rfp") == expectedRfp &&
            parsedJwt.getJWTClaimsSet().getIssueTime().toInstant().isBefore(Instant.now()) &&
            parsedJwt.getJWTClaimsSet().getExpirationTime().toInstant().isAfter(Instant.now())
  }

  private static boolean verifyJws(String jwt, String signingKey) {
    JWSObject jws = JWSObject.parse(jwt)
    JWSVerifier verifier = new MACVerifier(signingKey)
    return jws.verify(verifier)
  }
}
