package com.example.app.util

import com.example.app.models.AppConfig
import com.unboundid.scim2.client.ScimService
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider
import org.glassfish.jersey.client.ClientConfig

import javax.ws.rs.client.Client
import javax.ws.rs.client.ClientBuilder
import javax.ws.rs.client.ClientRequestContext
import javax.ws.rs.client.ClientRequestFilter
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
    ApacheConnectorProvider connectorProvider = new ApacheConnectorProvider()
    clientConfig.connectorProvider(connectorProvider)
    clientConfig.register(
            new ClientRequestFilter()
            {
              public void filter(ClientRequestContext requestContext)
                      throws IOException
              {
                requestContext.getHeaders().add(
                        "Authorization", "Bearer ${bearerToken}")
              }
            }
    )
    Client restClient = ClientBuilder.newClient(clientConfig)
    WebTarget target = restClient.target(new URI(config.getScimEndpoint()))
    return new ScimService(target)
  }
}
