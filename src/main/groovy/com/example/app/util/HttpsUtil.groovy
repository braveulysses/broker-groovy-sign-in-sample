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
import org.apache.http.client.config.RequestConfig
import org.apache.http.config.Registry
import org.apache.http.config.RegistryBuilder
import org.apache.http.conn.HttpClientConnectionManager
import org.apache.http.conn.socket.ConnectionSocketFactory
import org.apache.http.conn.socket.PlainConnectionSocketFactory
import org.apache.http.conn.ssl.DefaultHostnameVerifier
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager
import org.glassfish.jersey.apache.connector.ApacheClientProperties
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider
import org.glassfish.jersey.client.ClientConfig

import javax.net.ssl.HostnameVerifier
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
   * Creates a basic {@link SSLContext} instance that uses the JDK's default
   * trust manager.
   *
   * @return A basic SSLContext instance.
   */
  public static SSLContext createDefaultSSLContext() {
    SSLContext sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, null, null)
    return sslContext
  }

  /**
   * Creates an {@link SSLContext} instance that accepts all SSL connections.
   * This is completely insecure and should only be used during testing.
   *
   * @return An insecure SSLContext instance.
   */
  public static SSLContext createInsecureSSLContext() {
    SSLContext sslContext = SSLContext.getInstance("TLS")
    TrustManager[] trustManagers = [ new PermissiveTrustManager() ]
    sslContext.init(null, trustManagers, null)
    return sslContext
  }

  /**
   * Creates a {@link ClientConfig} instance for use with a Jersey client.
   * HTTP request handling will be backed by an Apache HttpClient instance.
   *
   * @param appConfig
   *          The application configuration. Used to determine if permissive
   *          HTTPS connection validation is desired.
   * @return A ClientConfig instance.
   */
  public static ClientConfig createClientConfig(AppConfig appConfig)
  {
    ClientConfig jerseyConfig = new ClientConfig()
    jerseyConfig.property(ApacheClientProperties.CONNECTION_MANAGER,
                          createClientConnectionManager(
                                  appConfig.isStrictHttpsValidation()))
    jerseyConfig.property(ApacheClientProperties.REQUEST_CONFIG,
                          RequestConfig.DEFAULT)
    ApacheConnectorProvider connectorProvider = new ApacheConnectorProvider()
    jerseyConfig.connectorProvider(connectorProvider)
    return jerseyConfig
  }

  private static HttpClientConnectionManager createClientConnectionManager(
          boolean useStrictHttpsValidation)
  {
    HttpClientConnectionManager clientConnectionManager =
            new PoolingHttpClientConnectionManager(
                    createConnectionSocketFactoryRegistry(useStrictHttpsValidation))
    return clientConnectionManager
  }

  private static Registry<ConnectionSocketFactory> createConnectionSocketFactoryRegistry(
          boolean useStrictHttpsValidation)
  {
    SSLContext sslContext
    if (useStrictHttpsValidation) {
      sslContext = createDefaultSSLContext()
    } else {
      sslContext = createInsecureSSLContext()
    }

    HostnameVerifier hostnameVerifier
    if (useStrictHttpsValidation) {
      hostnameVerifier = new DefaultHostnameVerifier()
    } else {
      hostnameVerifier = NoopHostnameVerifier.INSTANCE
    }

    final SSLConnectionSocketFactory sslConnectionSocketFactory =
            new SSLConnectionSocketFactory(sslContext, hostnameVerifier)
    return RegistryBuilder.<ConnectionSocketFactory>create()
            .register("http", PlainConnectionSocketFactory.getSocketFactory())
            .register("https", sslConnectionSocketFactory)
            .build()
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
