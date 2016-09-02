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
package com.example.app.services

import com.example.app.models.AppConfig
import com.example.app.util.HttpsUtil
import com.nimbusds.jose.jwk.JWKSet
import groovy.util.logging.Slf4j
import ratpack.exec.ExecController
import ratpack.exec.Execution
import ratpack.http.client.HttpClient
import ratpack.service.Service
import ratpack.service.StartEvent

import javax.inject.Inject
import java.util.concurrent.TimeUnit
import java.util.stream.Collectors

/**
 * Downloads the authentication server's JWK key set during startup,
 * periodically checking for updates.
 */
@Slf4j
class JwksService implements Service, Runnable {
  private AppConfig appConfig
  private URI jwksUri
  private HttpClient httpClient
  private boolean strictHttpsValidation = true

  @Inject
  public JwksService(HttpClient httpClient) {
    this.httpClient = httpClient
  }

  @Override
  public void onStart(StartEvent event) {
    appConfig = event.getRegistry().get(AppConfig)
    strictHttpsValidation = appConfig.isStrictHttpsValidation()
    jwksUri = appConfig.getJwksEndpoint()
    int fetchInterval = appConfig.getJwksFetchInterval()
    ExecController execController =
            event.getRegistry().get(ExecController)
    execController.getExecutor()
            .scheduleAtFixedRate(this, 0, fetchInterval, TimeUnit.SECONDS)
  }

  @Override
  public void run() {
    Execution.fork().start { execution ->
      httpClient.get(jwksUri) { requestSpec ->
        if (!strictHttpsValidation) {
          requestSpec.sslContext(HttpsUtil.createInsecureSSLContext())
        }
      }.onError { throwable ->
        throwable.printStackTrace()
      }.map { response ->
        return response.getBody().getText()
      }.then { body ->
        JWKSet publicKeys = JWKSet.parse(body)
        appConfig.setJwks(publicKeys)
        log.info("JWKS retrieved: {}", keyIds(publicKeys))
      }
    }
  }

  private static Set<String> keyIds(JWKSet jwks) {
    return jwks.getKeys().stream().map { key ->
      return key.getKeyID()
    }.collect(Collectors.toSet())
  }
}
