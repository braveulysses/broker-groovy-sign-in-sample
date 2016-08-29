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

import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

/**
 * HTTPS-related utility methods.
 */
final class HttpsUtil {
  /**
   * Creates an {@link SSLContext} instance that accepts all SSL connections.
   * This is completely insecure and should only be used during testing.
   *
   * @return An insecure SSLContext instance.
   */
  public static SSLContext createInsecureSSLContext() {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    TrustManager[] trustManagers = [ new PermissiveTrustManager() ]
    sslContext.init(null, trustManagers, null)
    return sslContext
  }

  private static class PermissiveTrustManager implements X509TrustManager {
    @Override
    void checkClientTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {
      // Do nothing
    }

    @Override
    void checkServerTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {
      // Do nothing
    }

    @Override
    X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0]
    }
  }
}
