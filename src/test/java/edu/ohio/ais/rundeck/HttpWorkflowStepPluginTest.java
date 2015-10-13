package edu.ohio.ais.rundeck;

import com.dtolabs.rundeck.core.execution.workflow.steps.PluginStepContextImpl;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepException;
import com.dtolabs.rundeck.core.utils.Base64;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import edu.ohio.ais.rundeck.util.OAuthClient;
import edu.ohio.ais.rundeck.util.OAuthClientTest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class HttpWorkflowStepPluginTest {
    protected static final String REMOTE_URL = "/trigger";
    protected static final String OAUTH_CLIENT_MAP_KEY = OAuthClientTest.CLIENT_ID + "@"
            + OAuthClientTest.BASE_URI + OAuthClientTest.ENDPOINT_TOKEN;

    protected HttpWorkflowStepPlugin plugin;
    protected OAuthClientTest oAuthClientTest = new OAuthClientTest();

    /**
     * Setup options for simple execution for the given method.
     * @param method HTTP Method to use.
     * @return Options for the execution.
     */
    public Map<String, Object> getExecutionOptions(String method) {
        Map<String, Object> options = new HashMap<>();

        options.put("remoteUrl", OAuthClientTest.BASE_URI + REMOTE_URL);
        options.put("method", method);

        return options;
    }

    /**
     * Setup options for execution for the given method using HTTP BASIC.
     * @param method HTTP Method to use.
     * @return Options for the execution.
     */
    public Map<String, Object> getBasicOptions(String method) {
        Map<String, Object> options = getExecutionOptions(method);

        options.put("username", OAuthClientTest.CLIENT_ID);
        options.put("password", OAuthClientTest.CLIENT_SECRET);
        options.put("authentication", HttpWorkflowStepPlugin.AUTH_BASIC);

        return options;
    }

    /**
     * Setup options for simple execution for the given method using OAuth 2.0.
     * @param method HTTP Method to use.
     * @return Options for the execution.
     */
    public Map<String, Object> getOAuthOptions(String method) {
        Map<String, Object> options = getBasicOptions(method);

        options.put("oauthTokenEndpoint", OAuthClientTest.BASE_URI + OAuthClientTest.ENDPOINT_TOKEN);
        options.put("oauthValidateEndpoint", OAuthClientTest.BASE_URI + OAuthClientTest.ENDPOINT_VALIDATE);
        options.put("authentication", HttpWorkflowStepPlugin.AUTH_OAUTH2);

        return options;
    }

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(18089);

    @Before
    public void setUp() {
        plugin = new HttpWorkflowStepPlugin();
        oAuthClientTest.setUp(); // We need to setup the OAuth endpoints too.

        // Test all endpoints by simply iterating.
        for(String method : HttpWorkflowStepPlugin.HTTP_METHODS) {
            // Simple endpoint
            WireMock.stubFor(WireMock.request(method, WireMock.urlEqualTo(REMOTE_URL)).atPriority(100)
                    .willReturn(WireMock.aResponse()
                            .withStatus(200)));

            // HTTP Basic
            WireMock.stubFor(WireMock.request(method, WireMock.urlEqualTo(REMOTE_URL))
                    .withHeader("Authorization", WireMock.equalTo("Basic " + Base64.encode(OAuthClientTest.CLIENT_ID + ":" + OAuthClientTest.CLIENT_SECRET)))
                    .willReturn(WireMock.aResponse()
                            .withStatus(200)));

            // OAuth with a fresh token
            WireMock.stubFor(WireMock.request(method, WireMock.urlEqualTo(REMOTE_URL))
                    .withHeader("Authorization", WireMock.equalTo("Bearer " + OAuthClientTest.ACCESS_TOKEN_VALID))
                    .willReturn(WireMock.aResponse()
                            .withStatus(200)));

            // OAuth with an expired token
            WireMock.stubFor(WireMock.request(method, WireMock.urlEqualTo(REMOTE_URL))
                    .withHeader("Authorization", WireMock.equalTo("Bearer " + OAuthClientTest.ACCESS_TOKEN_EXPIRED))
                    .willReturn(WireMock.aResponse()
                            .withStatus(401)));
        }
    }

    @Test()
    public void canCallSimpleEndpoint() throws StepException {
        for(String method : HttpWorkflowStepPlugin.HTTP_METHODS) {
            this.plugin.executeStep(new PluginStepContextImpl(), this.getExecutionOptions(method));
        }
    }

    @Test()
    public void canCallBasicEndpoint() throws StepException {
        for(String method : HttpWorkflowStepPlugin.HTTP_METHODS) {
            this.plugin.executeStep(new PluginStepContextImpl(), this.getBasicOptions(method));
        }
    }

    @Test()
    public void canCallOAuthEndpoint() throws StepException {
        for(String method : HttpWorkflowStepPlugin.HTTP_METHODS) {
            this.plugin.executeStep(new PluginStepContextImpl(), this.getOAuthOptions(method));
        }
    }

    @Test()
    public void canCallOAuthEndpointWithExpiredToken() throws StepException {
        this.plugin.oauthClients.put(OAUTH_CLIENT_MAP_KEY, this.oAuthClientTest.setupClient(OAuthClientTest.ACCESS_TOKEN_EXPIRED));

        for(String method : HttpWorkflowStepPlugin.HTTP_METHODS) {
            this.plugin.executeStep(new PluginStepContextImpl(), this.getOAuthOptions(method));
        }
    }

    @Test(expected = StepException.class)
    public void cannotCallOAuthEndpointWithCredentials() throws StepException {
        Map<String, Object> options = this.getOAuthOptions("GET");
        options.put("username", OAuthClientTest.INVALID_CLIENT_ID);
        options.put("password", OAuthClientTest.INVALID_CLIENT_SECRET);

        this.plugin.executeStep(new PluginStepContextImpl(), options);
    }
}
