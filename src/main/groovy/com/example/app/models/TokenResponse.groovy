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

import com.fasterxml.jackson.annotation.JsonProperty

/**
 * An OAuth 2/OpenID Connect token response.
 */
class TokenResponse {
  @JsonProperty("access_token")
  String accessToken
  @JsonProperty("refresh_token")
  String refreshToken
  @JsonProperty("id_token")
  String idToken
  @JsonProperty("token_type")
  String tokenType
  @JsonProperty("state")
  String state
  @JsonProperty("expires_in")
  Date expiresIn
  @JsonProperty("scope")
  Set<String> scopes

  public void setExpiresIn(long expiresIn) {
    this.expiresIn = new Date(expiresIn)
  }

  public void setScopes(String scope) {
    if (scope) {
      scopes = scope.split(' ') as Set
    }
  }
}
