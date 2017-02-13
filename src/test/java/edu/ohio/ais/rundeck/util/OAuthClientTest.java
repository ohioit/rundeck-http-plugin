package edu.ohio.ais.rundeck.util;

import com.dtolabs.rundeck.core.utils.Base64;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpResponseException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class OAuthClientTest {
    public static final String ACCESS_TOKEN_VALID = "1";
    public static final String ACCESS_TOKEN_EXPIRED = "2";
    public static final String ACCESS_TOKEN_CONFUSED_DEPUTY = "3";
    public static final String ACCESS_TOKEN_INVALID = "4";
    public static final String ACCESS_TOKEN_FOREVER_EXPIRED = "5";

    public static final String BASE_URI = "http://localhost:18089";

    public static final String ENDPOINT_TOKEN = "/token";
    public static final String ENDPOINT_VALIDATE = "/validate";

    public static final String CLIENT_SECRET = "mockSecret";

    public static final String CLIENT_VALID = "mockClient";
    public static final String CLIENT_FOREVER_EXPIRED = "foreverClient";
    public static final String CLIENT_INVALID = "mockInvalidClient";
    public static final String CLIENT_INVALID_GRANT = "mockMisconfiguredClient";
    public static final String CLIENT_INVALID_GRANT_NO_DESCRIPTION = "mockMisconfiguredClientNoDescription";

    public static final String ERROR_UNAUTHORIZED_GRANT_TYPE = "invalid_grant";
    public static final String ERROR_UNAUTHORIZED_GRANT_TYPE_DESCRIPTION = "Unauthorized grant type";

    /**
     * Setup an OAuth client with the above values.
     * @return OAuthClient
     */
    public OAuthClient setupClient() {
        OAuthClient client = new OAuthClient(OAuthClient.GrantType.CLIENT_CREDENTIALS);
        client.setCredentials(CLIENT_VALID, CLIENT_SECRET);
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
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Bearer " + ACCESS_TOKEN_VALID))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"client\": \"" + CLIENT_VALID + "\"}")));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Bearer " + ACCESS_TOKEN_CONFUSED_DEPUTY))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"client\": \"confused\"}")));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Bearer " + ACCESS_TOKEN_EXPIRED))
                .willReturn(WireMock.aResponse()
                        .withStatus(401)));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Bearer " + ACCESS_TOKEN_FOREVER_EXPIRED))
                .willReturn(WireMock.aResponse()
                        .withStatus(401)));
        WireMock.stubFor(WireMock.get(WireMock.urlEqualTo(ENDPOINT_VALIDATE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Bearer " + ACCESS_TOKEN_INVALID))
                .willReturn(WireMock.aResponse()
                        .withStatus(400)));

        // Token endpoints with a variety of access tokens.
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.CONTENT_TYPE, WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Basic " + Base64.encode(CLIENT_VALID + ":" + CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"access_token\":\"" + ACCESS_TOKEN_VALID + "\",\"token_type\":\"bearer\"}")));
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.CONTENT_TYPE, WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Basic " + Base64.encode(CLIENT_FOREVER_EXPIRED+ ":" + CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"access_token\":\"" + ACCESS_TOKEN_VALID + "\",\"token_type\":\"bearer\"}")));
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.CONTENT_TYPE, WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Basic " + Base64.encode(CLIENT_INVALID + ":" + CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(401)));
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.CONTENT_TYPE, WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Basic " + Base64.encode(CLIENT_INVALID_GRANT + ":" + CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(400)
                        .withHeader(HttpHeaders.CONTENT_TYPE, OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"error_description\":\"" + ERROR_UNAUTHORIZED_GRANT_TYPE_DESCRIPTION +
                                "\",\"error\":\"" + ERROR_UNAUTHORIZED_GRANT_TYPE + "\"}")));
        WireMock.stubFor(WireMock.post(WireMock.urlEqualTo(ENDPOINT_TOKEN))
                .withHeader(HttpHeaders.ACCEPT, WireMock.equalTo(OAuthClient.JSON_CONTENT_TYPE))
                .withHeader(HttpHeaders.CONTENT_TYPE, WireMock.equalTo(OAuthClient.FORM_CONTENT_TYPE))
                .withHeader(HttpHeaders.AUTHORIZATION, WireMock.equalTo("Basic " + Base64.encode(CLIENT_INVALID_GRANT_NO_DESCRIPTION + ":" + CLIENT_SECRET)))
                .withRequestBody(WireMock.matching(".*grant_type=client_credentials.*"))
                .willReturn(WireMock.aResponse()
                        .withStatus(400)
                        .withHeader(HttpHeaders.CONTENT_TYPE, OAuthClient.JSON_CONTENT_TYPE)
                        .withBody("{\"error\":\"" + ERROR_UNAUTHORIZED_GRANT_TYPE + "\"}")));
    }

    @Test()
    public void canBeInitialized() {
        OAuthClient client = setupClient();

        assertEquals(client.grantType, OAuthClient.GrantType.CLIENT_CREDENTIALS);
        assertEquals(client.clientId, CLIENT_VALID);
        assertEquals(client.clientSecret, CLIENT_SECRET);
        assertEquals(client.tokenEndpoint, BASE_URI + ENDPOINT_TOKEN);
        assertEquals(client.validateEndpoint, BASE_URI + ENDPOINT_VALIDATE);
        assertEquals(client.accessToken, null);
    }

    @Test
    public void canGetAccessToken() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient();
        String token = client.getAccessToken();

        assertEquals(token, ACCESS_TOKEN_VALID);
        assertEquals(client.accessToken, ACCESS_TOKEN_VALID);
    }

    @Test
    public void canInvalidateAccessToken() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient();
        client.getAccessToken();
        client.invalidateAccessToken();

        assertEquals(client.accessToken, null);
    }

    @Test
    public void canRefreshExpiredAccessToken() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_EXPIRED);
        client.doTokenValidate();

        assertEquals(client.accessToken, ACCESS_TOKEN_VALID);
    }

    @Test(expected = HttpResponseException.class)
    public void canHandleInvalidCredentials() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient();
        client.setCredentials(CLIENT_INVALID, CLIENT_SECRET);
        client.getAccessToken();
    }

    @Test(expected = HttpResponseException.class)
    public void canHandleInvalidToken() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_INVALID);
        client.doTokenValidate();
    }

    @Test(expected = OAuthClient.OAuthException.class)
    public void canHandleForeverExpiredToken() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_FOREVER_EXPIRED);
        client.setCredentials(CLIENT_FOREVER_EXPIRED, CLIENT_SECRET);
        client.doTokenValidate();
    }

    @Test(expected = OAuthClient.OAuthException.class)
    public void canHandleConfusedDeputy() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = setupClient(ACCESS_TOKEN_CONFUSED_DEPUTY);
        client.doTokenValidate();
    }

    @Test()
    public void canHandleMissingValidateEndpoint() throws HttpResponseException, IOException, OAuthClient.OAuthException {
        OAuthClient client = new OAuthClient(OAuthClient.GrantType.CLIENT_CREDENTIALS);
        client.setTokenEndpoint(BASE_URI + ENDPOINT_TOKEN);
        client.setCredentials(CLIENT_VALID, CLIENT_SECRET);
        client.doTokenValidate();

        assertEquals(client.accessToken, ACCESS_TOKEN_VALID);
    }

    @Test()
    public void canBuildErrorWithDescription() throws IOException, OAuthClient.OAuthException {
        OAuthClient client = this.setupClient();
        client.setCredentials(CLIENT_INVALID_GRANT, CLIENT_SECRET);

        try {
            client.doTokenRequest();
        } catch(HttpResponseException hce) {
            assertTrue(hce.getMessage().contains(ERROR_UNAUTHORIZED_GRANT_TYPE_DESCRIPTION));
            assertFalse(hce.getMessage().contains(ERROR_UNAUTHORIZED_GRANT_TYPE));
        }
    }

    @Test()
    public void canBuildErrorWithoutDescription() throws IOException, OAuthClient.OAuthException {
        OAuthClient client = this.setupClient();
        client.setCredentials(CLIENT_INVALID_GRANT_NO_DESCRIPTION, CLIENT_SECRET);

        try {
            client.doTokenRequest();
        } catch(HttpResponseException hce) {
            assertFalse(hce.getMessage().contains(ERROR_UNAUTHORIZED_GRANT_TYPE_DESCRIPTION));
            assertTrue(hce.getMessage().contains(ERROR_UNAUTHORIZED_GRANT_TYPE));
        }
    }
}
