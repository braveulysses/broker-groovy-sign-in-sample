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
package com.example.app.util

import com.example.app.exceptions.TokenValidationException
import com.example.app.models.AppConfig
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.SignedJWT

/**
 * Utility methods for working with JWT tokens.
 */
class TokenUtil {
  public static void verifyJws(SignedJWT jwt, JWK jwk)
          throws TokenValidationException {
    JWSVerifier verifier = new RSASSAVerifier((RSAKey) jwk)
    verifyJws(jwt, verifier)
  }

  public static void verifyJws(SignedJWT jwt, String sharedSecret)
          throws TokenValidationException {
    JWSVerifier verifier = new MACVerifier(sharedSecret)
    verifyJws(jwt, verifier)
  }

  public static void verifyJws(SignedJWT jwt, JWSVerifier verifier)
          throws TokenValidationException {
    if (!jwt.verify(verifier)) {
      throw new TokenValidationException("Token signature could not be verified")
    }
  }

  public static JWT verifySignedAccessToken(AppConfig config, String accessToken) {
    SignedJWT accessTokenJwt = SignedJWT.parse(accessToken)
    String kid = accessTokenJwt.getHeader().getKeyID()
    JWK jwk = config.getJwks().getKeyByKeyId(kid)
    verifyJws(accessTokenJwt, jwk)
    return accessTokenJwt
  }
}
