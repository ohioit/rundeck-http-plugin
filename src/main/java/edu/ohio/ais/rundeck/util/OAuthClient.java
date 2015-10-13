package edu.ohio.ais.rundeck.util;

import com.dtolabs.client.utils.HttpClientException;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Simple OAuth client to manage obtaining tokens and providing
 * them for HTTP requests.
 *
 * Currently this only supports the CLIENT_CREDENTIALS grant type.
 */
public class OAuthClient {
    private static final Log log = LogFactory.getLog(OAuthClient.class);

    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

    public static final String FIELD_GRANT_TYPE = "grant_type";
    public static final String FIELD_ACCESS_TOKEN = "access_token";

    public static final Integer STATUS_SUCCESS = 200;
    public static final Integer STATUS_AUTHORIZATION_REQUIRED = 401;

    public enum GrantType {
        CLIENT_CREDENTIALS
    }

    public static class OAuthException extends Exception {
        public OAuthException(String message) {
            super(message);
        }
    }

    String clientId;
    String clientSecret;

    GrantType grantType;

    String tokenEndpoint;
    String validateEndpoint;

    String accessToken;

    /**
     * Retrieve an access token with our client credentials.
     *
     * @throws UnirestException
     * @throws HttpClientException When a non 200 or 401 status code is returned.
     */
    void doTokenRequest() throws UnirestException, HttpClientException {
        this.accessToken = null;

        log.debug("Requesting access token from " + this.tokenEndpoint);

        HttpResponse<JsonNode> response = Unirest.post(this.tokenEndpoint)
                .basicAuth(this.clientId, this.clientSecret)
                .header("Accept", JSON_CONTENT_TYPE)
                .header("Content-Type", FORM_CONTENT_TYPE)
                .field(FIELD_GRANT_TYPE, this.grantType.name().toLowerCase())
                .asJson();

        if(response.getStatus() == STATUS_SUCCESS) {
            this.accessToken = response.getBody().getObject().getString(FIELD_ACCESS_TOKEN);
        } else {
            throw new HttpClientException(response.getStatusText());
        }
    }

    /**
     * Validate that the token we have is correct. This includes
     * verifying that the client ID on the token is our client ID. The endpoint
     * is called with a simple GET requests and expects a JSON response like
     * the following:
     *
     * <code>
     *     {
     *         ...
     *         "clientId": ${Client ID Value}
     *         ...
     *     }
     * </code>
     *
     * @throws HttpClientException When a status code other than 200 of 401 is returned
     * @throws UnirestException
     * @throws OAuthException When the Client ID on the token doesn't match our client ID.
     */
    void doTokenValidate() throws HttpClientException, UnirestException, OAuthException {
        if(this.accessToken == null) {
            this.doTokenRequest();
        }

        if(this.validateEndpoint != null) {
            log.debug("Validating access token at " + this.validateEndpoint);

            HttpResponse<JsonNode> response = Unirest.get(this.validateEndpoint)
                    .header("Authorization", "Bearer " + this.accessToken)
                    .header("Accept", JSON_CONTENT_TYPE)
                    .asJson();

            if (response.getStatus() == STATUS_SUCCESS) {
                String clientId = response.getBody().getObject().getString("clientId");

                if (!this.clientId.equals(clientId)) {
                    throw new OAuthException("Token received for a client other than us.");
                }
            } else if (response.getStatus() == STATUS_AUTHORIZATION_REQUIRED) {
                this.accessToken = null;
                doTokenRequest();
            } else {
                throw new HttpClientException(response.getStatusText());
            }
        } else {
            log.debug("No validate endpoint exists, skipping validation.");
        }
    }

    /**
     * Initialize the OAuth client with the specified grant type.
     *
     * @param grantType
     */
    public OAuthClient(GrantType grantType) {
        this.grantType = grantType;
    }

    /**
     * Set the credentials to use with this client.
     *
     * @param clientId
     * @param clientSecret
     */
    public void setCredentials(String clientId, String clientSecret) {
        log.trace("Setting credentials to " + this.clientId + ":" + this.clientSecret);

        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Set the endpoint at which we can fetch an OAuth token.
     *
     * @param tokenEndpoint Complete URI to the token endpoint.
     */
    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Set the endpoint at which we can validate an OAuth token.
     *
     * @param validateEndpoint Complete URI to the validate endpoint.
     */
    public void setValidateEndpoint(String validateEndpoint) {
        this.validateEndpoint = validateEndpoint;
    }

    /**
     * Invalidate our current access token.
     */
    public void invalidateAccessToken() {
        log.debug("Invalidating access token.");
        this.accessToken = null;
    }

    /**
     * Get our access token. If we don't have a token, attempt to get one. Note that this
     * is synchronous.
     *
     * @return The access token string.
     *
     * @throws HttpClientException If an HTTP status code we don't handle is returned.
     * @throws UnirestException
     * @throws OAuthException If our token is not valid (or other OAuth protocol issues)
     */
    public String getAccessToken() throws HttpClientException, UnirestException, OAuthException {
        if(this.accessToken == null) {
            this.doTokenValidate();
        }

        return this.accessToken;
    }
}
