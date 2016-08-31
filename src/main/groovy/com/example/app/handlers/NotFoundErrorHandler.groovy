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

import com.example.app.models.AppSession
import io.netty.handler.codec.http.HttpResponseStatus
import ratpack.error.ClientErrorHandler
import ratpack.handling.Context

import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * An error handler for 404 Page Not Found errors. This handler could actually
 * be used to handle any kind of client error, but only 404s are expected in
 * practice.
 */
class NotFoundErrorHandler implements ClientErrorHandler {
  @Override
  void error(Context ctx, int statusCode) throws Exception {
    AppSession.fromContext(ctx).then { AppSession appSession ->
      ctx.response.status(HttpResponseStatus.NOT_FOUND.code())
      ctx.render(handlebarsTemplate("exception-generic", [
              authenticated: appSession.getAuthenticated(),
              returnUri: ctx.getRequest().getUri(),
              message: "Page not found"
      ], "text/html"))
    }
  }
}
