package edu.ohio.ais.rundeck.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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

    protected HttpClient httpClient;
    protected ObjectMapper jsonParser = new ObjectMapper();

    String clientId;
    String clientSecret;

    GrantType grantType;

    String tokenEndpoint;
    String validateEndpoint;

    String accessToken;

    /**
     * Try and build a reasonable error from the response. We try to
     * use the optional "error_description" property if it's there, otherwise
     * we stick with the "error" property, which is required. For
     * implementations that don't comply with RFC 6749, we'll try to
     * gracefully return just the status text.
     *
     * @param response The HTTP response.
     * @return Error string
     */
    protected String buildError(HttpResponse response) {
        String error = response.getStatusLine().getReasonPhrase();

        try {
            JsonNode data = jsonParser.readTree(EntityUtils.toString(response.getEntity()));

            if(!data.isArray()) {
                if (data.has("error_description")) {
                    error += ": " + data.get("error_description").asText();
                } else if (data.has("error")) {
                    error += ": " + data.get("error").asText();
                }
            }
        } catch (IOException e) {
            log.error(e);
            error += ": Unable to parse error response: " + e.getMessage();
        }

        return error;
    }

    /**
     * Retrieve an access token with our client credentials.
     *
     * @throws IOException         When the HTTP request fails for some reason.
     * @throws HttpResponseException When a non 200 or 401 status code is returned.
     */
    void doTokenRequest() throws HttpResponseException, OAuthException, IOException {
        this.accessToken = null;

        log.debug("Requesting access token from " + this.tokenEndpoint);

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(FIELD_GRANT_TYPE, this.grantType.name().toLowerCase()));

        HttpUriRequest request = RequestBuilder.create("POST")
                .setUri(this.tokenEndpoint)
                .setHeader(HttpHeaders.AUTHORIZATION, "Basic " + com.dtolabs.rundeck.core.utils.Base64.encode(this.clientId + ":" + this.clientSecret))
                .setHeader(HttpHeaders.ACCEPT, JSON_CONTENT_TYPE)
                .setHeader(HttpHeaders.CONTENT_TYPE, FORM_CONTENT_TYPE)
                .setEntity(new UrlEncodedFormEntity(params)).build();

        HttpResponse response = this.httpClient.execute(request);

        if(response.getStatusLine().getStatusCode() == STATUS_SUCCESS) {
            JsonNode data = jsonParser.readTree(EntityUtils.toString(response.getEntity()));
            this.accessToken = data.get(FIELD_ACCESS_TOKEN).asText();
        } else {
            throw new HttpResponseException(response.getStatusLine().getStatusCode(), buildError(response));
        }

        this.doTokenValidate(true);
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
     * @throws HttpResponseException When a status code other than 200 of 401 is returned
     * @throws IOException
     * @throws OAuthException When the Client ID on the token doesn't match our client ID.
     */
    void doTokenValidate() throws HttpResponseException, IOException, OAuthException {
        this.doTokenValidate(false);
    }

    /**
     * As in doTokenValidate(), validate that the token is correct. In this case we
     * can specify that the token has _just_ been retrieved so that we don't try to
     * retrieve it again if validate fails.
     *
     * @param newToken True if this is a brand new token and we shouldn't try to get
     *                 a new on 401.a
     * @throws HttpResponseException
     * @throws IOException
     * @throws OAuthException
     */
    void doTokenValidate(Boolean newToken) throws HttpResponseException, IOException, OAuthException {
        if(this.accessToken == null) {
            this.doTokenRequest();
        }

        if(this.validateEndpoint != null) {
            log.debug("Validating access token at " + this.validateEndpoint);

            HttpUriRequest request = RequestBuilder.create("GET")
                    .setUri(this.validateEndpoint)
                    .setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + this.accessToken)
                    .setHeader(HttpHeaders.ACCEPT, JSON_CONTENT_TYPE)
                    .build();

            HttpResponse response = this.httpClient.execute(request);

            if (response.getStatusLine().getStatusCode() == STATUS_SUCCESS) {
                JsonNode data = jsonParser.readTree(EntityUtils.toString(response.getEntity()));
                String clientId = data.get("client").asText();

                if (!this.clientId.equals(clientId)) {
                    throw new OAuthException("Token received for a client other than us.");
                }
            } else if (response.getStatusLine().getStatusCode() == STATUS_AUTHORIZATION_REQUIRED) {
                this.accessToken = null;

                if(newToken) {
                    throw new OAuthException("Newly acquired token is still not valid.");
                } else {
                    doTokenRequest();
                }
            } else {
                throw new HttpResponseException(response.getStatusLine().getStatusCode(), buildError(response));
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
        this.httpClient = HttpClientBuilder.create()
                .disableAuthCaching()
                .disableAutomaticRetries()
                .build();

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
     * @throws HttpResponseException If an HTTP status code we don't handle is returned.
     * @throws IOException
     * @throws OAuthException If our token is not valid (or other OAuth protocol issues)
     */
    public String getAccessToken() throws HttpResponseException, IOException, OAuthException {
        if(this.accessToken == null) {
            this.doTokenValidate();
        }

        return this.accessToken;
    }
}
