package edu.ohio.ais.rundeck.util;

import static org.junit.Assert.assertEquals;

import com.dtolabs.client.utils.HttpClientException;
import com.dtolabs.rundeck.core.utils.Base64;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class OAuthClientTest {
    public static final String ACCESS_TOKEN_VALID = "1";
    public static final String ACCESS_TOKEN_EXPIRED = "2";
    public static final String ACCESS_TOKEN_CONFUSED_DEPUTY = "3";
    public static final String ACCESS_TOKEN_INVALID = "4";
    public static final String ACCESS_TOKEN_FOREVER_EXPIRED = "5";

    public static final String BASE_URI = "http://localhost:18089";

    public static final String ENDPOINT_TOKEN = "/token";
    public static final String ENDPOINT_VALIDATE = "/validate";

    public static final String CLIENT_ID = "mockClient";
    public static final String CLIENT_SECRET = "mockSecret";

    public static final String FOREVER_EXPIRED_CLIENT_ID = "foreverClient";
    public static final String FOREVER_EXPIRED_CLIENT_SECRET = "foreverClientSecret";

    public static final String INVALID_CLIENT_ID = "mockInvalidClient";
    public static final String INVALID_CLIENT_SECRET = "mockInvalidClientSecret";

    /**
     * Setup an OAuth client with the above values.
     * @return OAuthClient
     */
    public OAuthClient setupClient() {
        OAuthClient client = new OAuthClient(OAuthClient.GrantType.CLIENT_CREDENTIALS);
        client.setCredentials(CLIENT_ID, CLIENT_SECRET);
        client.setTokenEndpoint(BASE_URI + ENDPOINT_TOKEN);
        client.setValidateEndpoint(BASE_URI + ENDPOINT_VALIDATE);

        return client;
    }

    /**
     * Setup an OAuth client with the above values but pre-set with
     * the supplied access token.
     *
     * @param accessToken Access token string.
     * @return OAuthClient
     */
    public OAuthClient setupClient(String accessToken) {
        OAuthClient client = setupClient();
        client.accessToken = accessToken;

        return client;
    }

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(18089);

    @Before
    public void setUp() {
        // Validate endpoints with a variety of access tokens.
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader("Accept", WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader("Authorization", WireMock.equalTo("Bearer " + ACCESS_TOKEN_VALID))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"client\": \"" + CLIENT_ID + "\"}")));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader("Accept", WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader("Authorization", WireMock.equalTo("Bearer " + ACCESS_TOKEN_CONFUSED_DEPUTY))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"client\": \"confused\"}")));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader("Authorization", WireMock.equalTo("Bearer " + ACCESS_TOKEN_EXPIRED))
                .willReturn(WireMock.aResponse()
                        .withStatus(401)));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader("Authorization", WireMock.equalTo("Bearer " + ACCESS_TOKEN_FOREVER_EXPIRED))
                .willReturn(WireMock.aResponse()
                        .withStatus(401)));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader("Authorization", WireMock.equalTo("Bearer " + ACCESS_TOKEN_INVALID))
                .willReturn(WireMock.aResponse()
                        .withStatus(400)));

        // Token endpoints with a variety of access tokens.
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader("Accept", WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader("Content-Type", WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader("Authorization", WireMock.equalTo("Basic " + Base64.encode(CLIENT_ID + ":" + CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"access_token\":\"" + ACCESS_TOKEN_VALID + "\",\"token_type\":\"bearer\"}")));
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader("Accept", WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader("Content-Type", WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader("Authorization", WireMock.equalTo("Basic " + Base64.encode(FOREVER_EXPIRED_CLIENT_ID + ":" + FOREVER_EXPIRED_CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"access_token\":\"" + ACCESS_TOKEN_VALID + "\",\"token_type\":\"bearer\"}")));
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader("Accept", WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader("Content-Type", WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader("Authorization", WireMock.equalTo("Basic " + Base64.encode(INVALID_CLIENT_ID + ":" + INVALID_CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(401)));
    }

    @Test()
    public void canBeInitialized() {
        OAuthClient client = setupClient();

        assertEquals(client.grantType, OAuthClient.GrantType.CLIENT_CREDENTIALS);
        assertEquals(client.clientId, CLIENT_ID);
        assertEquals(client.clientSecret, CLIENT_SECRET);
        assertEquals(client.tokenEndpoint, BASE_URI + ENDPOINT_TOKEN);
        assertEquals(client.validateEndpoint, BASE_URI + ENDPOINT_VALIDATE);
        assertEquals(client.accessToken, null);
    }

    @Test
    public void canGetAccessToken() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient();
        String token = client.getAccessToken();

        assertEquals(token, ACCESS_TOKEN_VALID);
        assertEquals(client.accessToken, ACCESS_TOKEN_VALID);
    }

    @Test
    public void canInvalidateAccessToken() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient();
        client.getAccessToken();
        client.invalidateAccessToken();

        assertEquals(client.accessToken, null);
    }

    @Test
    public void canRefreshExpiredAccessToken() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_EXPIRED);
        client.doTokenValidate();

        assertEquals(client.accessToken, ACCESS_TOKEN_VALID);
    }

    @Test(expected = HttpClientException.class)
    public void canHandleInvalidCredentials() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient();
        client.setCredentials(INVALID_CLIENT_ID, INVALID_CLIENT_SECRET);
        client.getAccessToken();
    }

    @Test(expected = HttpClientException.class)
    public void canHandleInvalidToken() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_INVALID);
        client.doTokenValidate();
    }

    @Test(expected = OAuthClient.OAuthException.class)
    public void canHandleForeverExpiredToken() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_FOREVER_EXPIRED);
        client.setCredentials(FOREVER_EXPIRED_CLIENT_ID, FOREVER_EXPIRED_CLIENT_SECRET);
        client.doTokenValidate();
    }

    @Test(expected = OAuthClient.OAuthException.class)
    public void canHandleConfusedDeputy() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_CONFUSED_DEPUTY);
        client.doTokenValidate();
    }

    @Test()
    public void canHandleMissingValidateEndpoint() throws HttpClientException, UnirestException, OAuthClient.OAuthException {
        OAuthClient client = new OAuthClient(OAuthClient.GrantType.CLIENT_CREDENTIALS);
        client.setTokenEndpoint(BASE_URI + ENDPOINT_TOKEN);
        client.setCredentials(CLIENT_ID, CLIENT_SECRET);
        client.doTokenValidate();

        assertEquals(client.accessToken, ACCESS_TOKEN_VALID);
    }
}
