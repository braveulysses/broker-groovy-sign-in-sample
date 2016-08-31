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
import com.example.app.exceptions.TokenValidationException
import com.example.app.models.AppSession
import groovy.util.logging.Slf4j
import io.netty.handler.codec.http.HttpResponseStatus
import ratpack.error.ServerErrorHandler
import ratpack.handling.Context

import java.nio.charset.StandardCharsets

import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * This is a simple default implementation of {@link ServerErrorHandler}.
 */
@Slf4j
class DefaultServerErrorHandler implements ServerErrorHandler {
  @Override
  void error(Context ctx, Throwable throwable) throws Exception {
    String error = "Error at URI: /${ctx.getRequest().getUri()}"
    log.error(error, throwable)

    AppSession.fromContext(ctx).then { AppSession appSession ->
      ctx.response.status(HttpResponseStatus.INTERNAL_SERVER_ERROR.code())

      if (throwable.getClass().isAssignableFrom(CallbackErrorException)) {
        ctx.render(handlebarsTemplate("exception-callback-error", [
                authenticated   : appSession.getAuthenticated(),
                returnUri       : ctx.getRequest().getUri(),
                error           : ((CallbackErrorException) throwable).getError(),
                errorDescription: ((CallbackErrorException) throwable).getErrorDescription()
        ], "text/html"))
      } else if (throwable.getClass().isAssignableFrom(CallbackValidationException)
              || throwable.getClass().isAssignableFrom(TokenValidationException)) {
        ctx.render(handlebarsTemplate("exception-callback-validation", [
                authenticated: appSession.getAuthenticated(),
                returnUri: ctx.getRequest().getUri(),
                error: throwable.getMessage()
        ], "text/html"))
      } else {
        ctx.render(handlebarsTemplate("exception-generic", [
                authenticated: appSession.getAuthenticated(),
                returnUri: ctx.getRequest().getUri(),
                message: throwable.getMessage(),
                stackTrace: stackTrace(throwable)
        ], "text/html"))
      }
    }
  }

  private static String stackTrace(Throwable throwable) {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream()
    PrintStream printStream = new PrintStream(outputStream)
    throwable.printStackTrace(printStream)
    return new String(outputStream.toByteArray(), StandardCharsets.UTF_8)
  }
}
