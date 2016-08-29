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
import groovy.util.logging.Slf4j
import ratpack.service.Service
import ratpack.service.StartEvent

import java.security.SecureRandom

/**
 * This is called at startup and initializes any configuration properties
 * requiring a dynamic value, such as the application signing key.
 */
@Slf4j
class ConfigService implements Service {
  @Override
  public void onStart(StartEvent event) {
    AppConfig appConfig = event.getRegistry().get(AppConfig)
    log.info("Generating application signing key")
    SecureRandom random = new SecureRandom()
    byte[] signingKeyBytes = new byte[32]
    random.nextBytes(signingKeyBytes)
    appConfig.setSigningKey(new String(signingKeyBytes))
  }
}
