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

import com.example.app.models.AppConfig
import com.unboundid.scim2.client.ScimService
import com.unboundid.scim2.common.GenericScimResource
import org.glassfish.jersey.client.ClientConfig
import org.glassfish.jersey.client.oauth2.OAuth2ClientSupport
import ratpack.http.HttpUrlBuilder

import javax.ws.rs.client.Client
import javax.ws.rs.client.ClientBuilder
import javax.ws.rs.client.WebTarget

/**
 * This class provides a factory for creating SCIM client instances.
 */
class ScimClient {
  /**
   * Creates a {@link ScimService} instance.
   *
   * @param config
   *          The application configuration.
   * @param bearerToken
   *          The bearer token to present when making requests.
   * @return A ScimService instance.
   */
  public static ScimService createInstance(AppConfig config, String bearerToken) {
    ClientConfig clientConfig = HttpsUtil.createClientConfig(config)
    Client restClient = ClientBuilder.newClient(clientConfig)
            .register(OAuth2ClientSupport.feature(bearerToken))
    WebTarget target = restClient.target(baseScimEndpoint(config))
    return new ScimService(target)
  }

  public static GenericScimResource me(AppConfig config, String bearerToken) {
    ScimService scimService = createInstance(config, bearerToken)
    URI meEndpoint = HttpUrlBuilder.base(baseScimEndpoint(config))
            .path("Me")
            .build()
    return scimService.retrieve(meEndpoint, GenericScimResource)
  }

  private static URI baseScimEndpoint(AppConfig config) {
    return HttpUrlBuilder.base(config.getScimEndpoint())
            .path("scim/v2")
            .build()
  }
}
