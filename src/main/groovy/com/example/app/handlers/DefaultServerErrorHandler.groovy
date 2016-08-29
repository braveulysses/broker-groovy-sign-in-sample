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

import groovy.util.logging.Slf4j
import io.netty.handler.codec.http.HttpResponseStatus
import ratpack.error.ServerErrorHandler
import ratpack.handling.Context

/**
 * This is a simple default implementation of {@link ServerErrorHandler}.
 */
@Slf4j
class DefaultServerErrorHandler implements ServerErrorHandler {
  @Override
  void error(Context ctx, Throwable throwable) throws Exception {
    String error = "Error at URI: /${ctx.getRequest().getUri()}"
    log.error(error, throwable)
    ctx.response.status(HttpResponseStatus.INTERNAL_SERVER_ERROR.code())
            .send(throwable.getMessage())
  }
}
