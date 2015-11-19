package edu.ohio.ais.rundeck;

import com.dtolabs.rundeck.core.execution.workflow.steps.FailureReason;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepException;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepFailureReason;
import com.dtolabs.rundeck.core.plugins.Plugin;
import com.dtolabs.rundeck.core.plugins.configuration.Describable;
import com.dtolabs.rundeck.core.plugins.configuration.Description;
import com.dtolabs.rundeck.core.plugins.configuration.PropertyScope;
import com.dtolabs.rundeck.plugins.ServiceNameConstants;
import com.dtolabs.rundeck.plugins.step.PluginStepContext;
import com.dtolabs.rundeck.plugins.step.StepPlugin;
import com.dtolabs.rundeck.plugins.util.DescriptionBuilder;
import com.dtolabs.rundeck.plugins.util.PropertyBuilder;
import com.mashape.unirest.http.HttpMethod;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.mashape.unirest.request.HttpRequest;
import edu.ohio.ais.rundeck.util.OAuthClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Main implementation of the plugin. This will handle fetching
 * tokens when they're expired and sending the appropriate request.
 */
@Plugin(name = HttpWorkflowStepPlugin.SERVICE_PROVIDER_NAME, service = ServiceNameConstants.WorkflowStep)
public class HttpWorkflowStepPlugin implements StepPlugin, Describable {
    private static final Log log = LogFactory.getLog(HttpWorkflowStepPlugin.class);

    /**
     * Maximum number of attempts with which to try the request.
     */
    private static final Integer MAX_ATTEMPTS = 5;

    public static final String SERVICE_PROVIDER_NAME = "edu.ohio.ais.rundeck.HttpWorkflowStepPlugin";
    public static final String[] HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};
    public static final String AUTH_NONE = "None";
    public static final String AUTH_BASIC = "Basic";
    public static final String AUTH_OAUTH2 = "OAuth 2.0";

    /**
     * Synchronized map of all existing OAuth clients. This is indexed by
     * the Client ID and the token URL so that we can store and re-use access tokens.
     */
    final Map<String, OAuthClient> oauthClients = Collections.synchronizedMap(new HashMap<String, OAuthClient>());

    private enum Reason implements FailureReason {
        OAuthFailure,   // Failure from the OAuth protocol
        HTTPFailure     // Any HTTP related failures.
    }

    /**
     * Setup our plugin description, including all of the various configurable
     * options.
     *
     * @see <a href="http://rundeck.org/docs/developer/plugin-development.html#plugin-descriptions">Plugin Descriptions</a>
     *
     * @return The plugin description
     */
    @Override
    public Description getDescription() {
        return DescriptionBuilder.builder()
                .name(SERVICE_PROVIDER_NAME)
                .title("HTTP Request Step")
                .description("Performs an HTTP request with or without authentication")
                .property(PropertyBuilder.builder()
                    .string("remoteUrl")
                    .title("Remote URL")
                    .description("HTTP URL to which to make the request.")
                    .required(true)
                    .build())
                .property(PropertyBuilder.builder()
                    .select("method")
                    .title("HTTP Method")
                    .description("HTTP method used to make the request.")
                    .required(true)
                    .defaultValue("GET")
                    .values(HTTP_METHODS)
                    .build())
                .property(PropertyBuilder.builder()
                    .select("authentication")
                    .title("Authentication")
                    .description("Authentication mechanism to use.")
                    .required(false)
                    .defaultValue(AUTH_NONE)
                    .values(AUTH_NONE, AUTH_BASIC, AUTH_OAUTH2)
                    .build())
                .property(PropertyBuilder.builder()
                    .string("username")
                    .title("Username/Client ID")
                    .description("Username or Client ID to use for authentication.")
                    .required(false)
                    .scope(PropertyScope.Project)
                    .build())
                .property(PropertyBuilder.builder()
                    .string("password")
                    .title("Password/Client Secret")
                    .description("Password or Client Secret to use for authentication.")
                    .required(false)
                    .scope(PropertyScope.Project)
                    .build())
                .property(PropertyBuilder.builder()
                    .string("oauthTokenEndpoint")
                    .title("OAuth Token URL")
                    .description("OAuth 2.0 Token Endpoint URL at which to obtain tokens.")
                    .required(false)
                    .scope(PropertyScope.Project)
                    .build())
                .property(PropertyBuilder.builder()
                    .string("oauthValidateEndpoint")
                    .title("OAuth Validate URL")
                    .description("OAuth 2.0 Validate Endpoint URL at which to obtain validate token responses.")
                    .required(false)
                    .scope(PropertyScope.Project)
                    .build())
                .build();
    }

    /**
     * Execute a single request. This will call itself if it needs to refresh an OAuth token.
     *
     * @param options All of the options provided to the plugin execution
     * @param request The HTTP request we're supposed to execute
     * @param attempts The attempt number
     * @throws StepException Thrown when any error occurs
     */
    private void doRequest(Map<String, Object> options, HttpRequest request, Integer attempts) throws StepException {
        if(attempts > MAX_ATTEMPTS) {
            throw new StepException("Unable to complete request after maximum number of attempts.", StepFailureReason.IOFailure);
        }
        try {
            // We don't really care what the response data is at this point.
            HttpResponse<String> response = request.asString();

            // Sometimes we may need to refresh our OAuth token.
            if(response.getStatus() == OAuthClient.STATUS_AUTHORIZATION_REQUIRED) {
                log.debug("Warning: Got authorization required exception from " + request.getUrl());

                // But only if we actually use OAuth for authentication
                if(options.containsKey("authentication")) {
                    if(options.get("authentication").toString().equals(AUTH_BASIC)) {
                        throw new StepException("Remote URL requires authentication but does not support BASIC.", StepFailureReason.ConfigurationFailure);
                    } else if(options.get("authentication").toString().equals(AUTH_OAUTH2)) {
                        log.debug("Attempting to refresh OAuth token and try again...");
                        String accessToken;

                        // Another thread might be trying to do the same thing.
                        synchronized(this.oauthClients) {
                            String clientKey = options.get("username").toString() + "@" + options.get("oauthTokenEndpoint").toString();

                            OAuthClient client = this.oauthClients.get(clientKey);
                            client.invalidateAccessToken();

                            try {
                                accessToken = client.getAccessToken();
                            } catch(Exception e) {
                                StepException se = new StepException("Error refreshing OAuth Access Token: " + e.getMessage(),
                                        Reason.OAuthFailure);
                                se.initCause(e);
                                throw se;
                            }

                            // Don't forget to update the client map in case something changed
                            this.oauthClients.put(clientKey, client);
                        }

                        // Build a new request and call `doRequest` again.
                        request = new HttpRequest(HttpMethod.valueOf(options.get("method").toString()), options.get("remoteUrl").toString());
                        request.header("Authorization", "Bearer " + accessToken);

                        log.trace("Authentication header set to Bearer " + accessToken);

                        this.doRequest(options, request, attempts + 1);
                    } else {
                        throw new StepException("Remote URL requires authentication.", StepFailureReason.ConfigurationFailure);
                    }
                } else {
                    throw new StepException("Remote URL requires authentication.", StepFailureReason.ConfigurationFailure);
                }
            } else if(response.getStatus() >= 400) {
                String message = "Error when sending request";

                if(response.getStatusText().length() > 0) {
                    message += ": " + response.getStatusText();
                } else {
                    message += ": " + Integer.toString(response.getStatus()) + " Error";
                }

                if(response.getBody().length() > 0) {
                    message += ": " + response.getBody();
                }

                throw new StepException(message, Reason.HTTPFailure);
            }
        } catch (UnirestException e) {
            StepException se = new StepException("Error when sending request: " + e.getMessage(), Reason.HTTPFailure);
            se.initCause(e);
            throw se;
        }
    }

    @Override
    public void executeStep(PluginStepContext pluginStepContext, Map<String, Object> options) throws StepException {
        String authHeader = null;

        // Parse out the options
        String remoteUrl = options.containsKey("remoteUrl") ? options.get("remoteUrl").toString() : null;
        String method = options.containsKey("method") ? options.get("method").toString() : null;
        String authentication = options.containsKey("authentication") ? options.get("authentication").toString() : AUTH_NONE;

        if(remoteUrl == null || method == null) {
            throw new StepException("Remote URL and Method are required.", StepFailureReason.ConfigurationFailure);
        }

        if(authentication.equals(AUTH_BASIC)) {
            // Setup the authentication header for BASIC
            String username = options.containsKey("username") ? options.get("username").toString() : null;
            String password = options.containsKey("password") ? options.get("password").toString() : null;
            if(username == null || password == null) {
                throw new StepException("Username and password not provided for BASIC Authentication",
                        StepFailureReason.ConfigurationFailure);
            }

            authHeader = username + ":" + password;
        } else if (authentication.equals(AUTH_OAUTH2)) {
            // Get an OAuth token and setup the auth header for OAuth
            String tokenEndpoint = options.containsKey("oauthTokenEndpoint") ? options.get("oauthTokenEndpoint").toString() : null;
            String validateEndpoint = options.containsKey("oauthValidateEndpoint") ? options.get("oauthValidateEndpoint").toString() : null;
            String clientId = options.containsKey("username") ? options.get("username").toString() : null;
            String clientSecret = options.containsKey("password") ? options.get("password").toString() : null;

            if(tokenEndpoint == null) {
                throw new StepException("Token endpoint not provided for OAuth 2.0 Authentication.",
                        StepFailureReason.ConfigurationFailure);
            }

            String clientKey = clientId + "@" + tokenEndpoint;
            String accessToken;

            // Another thread may be trying to do the same thing.
            synchronized(this.oauthClients) {
                OAuthClient client;

                if(this.oauthClients.containsKey(clientKey)) {
                    // Update the existing client with our options if it exists.
                    // We do this so that changes to configuration will always
                    // update clients on next run.
                    log.trace("Found existing OAuth client with key " + clientKey);
                    client = this.oauthClients.get(clientKey);
                    client.setCredentials(clientId, clientSecret);
                    client.setValidateEndpoint(validateEndpoint);
                } else {
                    // Create a brand new client
                    log.trace("Creating new OAuth client with key " + clientKey);
                    client = new OAuthClient(OAuthClient.GrantType.CLIENT_CREDENTIALS);
                    client.setCredentials(clientId, clientSecret);
                    client.setTokenEndpoint(tokenEndpoint);
                    client.setValidateEndpoint(validateEndpoint);
                }

                // Grab the access token
                try {
                    log.trace("Attempting to fetch access token...");
                    accessToken = client.getAccessToken();
                } catch(Exception ex) {
                    StepException se = new StepException("Error obtaining OAuth Access Token: " + ex.getMessage(),
                            Reason.OAuthFailure);
                    se.initCause(ex);
                    throw se;
                }

                this.oauthClients.put(clientKey, client);
            }

            authHeader = "Bearer " + accessToken;
        }

        // Setup the request and process it.
        HttpRequest request = new HttpRequest(HttpMethod.valueOf(method), remoteUrl);

        log.debug("Creating HTTP " + request.getHttpMethod() + " request to " + request.getUrl());

        if(authHeader != null) {
            log.trace("Authentication header set to " + authHeader);
            request.header("Authorization", authHeader);
        }

        this.doRequest(options, request, 1);
    }
}
