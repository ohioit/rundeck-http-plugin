package edu.ohio.ais.rundeck;

import com.dtolabs.rundeck.core.dispatcher.DataContextUtils;
import com.dtolabs.rundeck.core.execution.workflow.steps.FailureReason;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepException;
import com.dtolabs.rundeck.core.execution.workflow.steps.StepFailureReason;
import com.dtolabs.rundeck.core.plugins.Plugin;
import com.dtolabs.rundeck.core.plugins.configuration.Describable;
import com.dtolabs.rundeck.core.plugins.configuration.Description;
import com.dtolabs.rundeck.core.plugins.configuration.StringRenderingConstants;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import com.dtolabs.rundeck.plugins.ServiceNameConstants;
import com.dtolabs.rundeck.plugins.step.PluginStepContext;
import com.dtolabs.rundeck.plugins.step.StepPlugin;
import com.dtolabs.rundeck.plugins.util.DescriptionBuilder;
import com.dtolabs.rundeck.plugins.util.PropertyBuilder;
import com.esotericsoftware.yamlbeans.YamlReader;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import edu.ohio.ais.rundeck.util.OAuthClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.dom4j.DocumentHelper;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

    /**
     * Default request timeout for execution. This only times out the
     * request for the URL, not OAuth authentication.
     */
    private static final Integer DEFAULT_TIMEOUT = 30*1000;

    public static final String SERVICE_PROVIDER_NAME = "edu.ohio.ais.rundeck.HttpWorkflowStepPlugin";
    public static final String[] HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};
    public static final String AUTH_NONE = "None";
    public static final String AUTH_BASIC = "Basic";
    public static final String AUTH_OAUTH2 = "OAuth 2.0";
    public static final String XML_FORMAT = "xml";
    public static final String JSON_FORMAT = "json";

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
                        .string("headers")
                        .title("Headers")
                        .description("Add headers in json or yaml format.")
                        .renderingAsTextarea()
                        .build())
                .property(PropertyBuilder.builder()
                        .string("body")
                        .title("Body")
                        .description("Add Body.")
                        .renderingAsTextarea()
                        .build())
                .property(PropertyBuilder.builder()
                    .integer("timeout")
                    .title("Request Timeout")
                    .description("How long to wait for a request to complete before failing.")
                    .defaultValue(DEFAULT_TIMEOUT.toString())
                    .build())
                .property(PropertyBuilder.builder()
                    .booleanType("sslVerify")
                    .title("Validate SSL Certificates")
                    .description("Validate that SSL certificates are trusted, match the hostname, are not expited, etc.")
                    .defaultValue("true")
                    .build())
                .property(PropertyBuilder.builder()
                        .select("authentication")
                        .title("Authentication")
                        .description("Authentication mechanism to use.")
                        .required(false)
                        .defaultValue(AUTH_NONE)
                        .values(AUTH_NONE, AUTH_BASIC, AUTH_OAUTH2)
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                        .build())
                .property(PropertyBuilder.builder()
                    .string("username")
                    .title("Username/Client ID")
                    .description("Username or Client ID to use for authentication.")
                    .required(false)
                    .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                    .build())
                .property(PropertyBuilder.builder()
                    .string("password")
                    .title("Password/Client Secret")
                    .description("Password or Client Secret to use for authentication.")
                    .required(false)
                    .renderingOption(StringRenderingConstants.SELECTION_ACCESSOR_KEY,
                            StringRenderingConstants.SelectionAccessor.STORAGE_PATH)
                    .renderingOption(StringRenderingConstants.STORAGE_PATH_ROOT_KEY, "keys")
                    .renderingOption(StringRenderingConstants.STORAGE_FILE_META_FILTER_KEY, "Rundeck-data-type=password")
                    .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                    .build())
                .property(PropertyBuilder.builder()
                    .string("oauthTokenEndpoint")
                    .title("OAuth Token URL")
                    .description("OAuth 2.0 Token Endpoint URL at which to obtain tokens.")
                    .required(false)
                    .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                    .build())
                .property(PropertyBuilder.builder()
                    .string("oauthValidateEndpoint")
                    .title("OAuth Validate URL")
                    .description("OAuth 2.0 Validate Endpoint URL at which to obtain validate token responses.")
                    .required(false)
                    .renderingOption(StringRenderingConstants.GROUP_NAME,"Authentication")
                    .build())
                .property(PropertyBuilder.builder()
                        .booleanType("checkResponseCode")
                        .title("Check Response Code?")
                        .description("Set if you want to check response code.")
                        .defaultValue("false")
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Check Response")
                        .build())
                .property(PropertyBuilder.builder()
                        .string("responseCode")
                        .title("Response Code")
                        .description("Response Code expected, the step will fail if the response code is different.")
                        .required(false)
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Check Response")
                        .build())
                .property(PropertyBuilder.builder()
                        .booleanType("printResponse")
                        .title("Print Response?")
                        .description("Set if the response needs to be printed.")
                        .defaultValue("false")
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Print")
                        .build())
                .property(PropertyBuilder.builder()
                        .booleanType("printResponseToFile")
                        .title("Print Response to File?")
                        .description("Set if you want to print the response content to a file.")
                        .defaultValue("false")
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Print")
                        .build())
                .property(PropertyBuilder.builder()
                        .string("file")
                        .title("File Path")
                        .description("File path where you will write the response.")
                        .required(false)
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Print")
                        .build())
                .property(PropertyBuilder.builder()
                        .booleanType("proxySettings")
                        .title("Use Proxy Settings?")
                        .description("Set if you want to use a proxy.")
                        .defaultValue("false")
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Proxy Settings")
                        .build())
                .property(PropertyBuilder.builder()
                        .string("proxyIP")
                        .title("Proxy IP")
                        .description("Proxy to use for this request")
                        .required(false)
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Proxy Settings")
                        .build())
                .property(PropertyBuilder.builder()
                        .integer("proxyPort")
                        .title("Proxy Port")
                        .description("Proxy port to use for this request")
                        .renderingOption(StringRenderingConstants.GROUP_NAME,"Proxy Settings")
                        .required(false)
                        .build())
                .build();
    }

    protected CloseableHttpClient getHttpClient(Map<String, Object> options) throws GeneralSecurityException {
        HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

        httpClientBuilder.disableAuthCaching();
        httpClientBuilder.disableAutomaticRetries();

        if(options.containsKey("sslVerify") && !Boolean.parseBoolean(options.get("sslVerify").toString())) {
            log.debug("Disabling all SSL certificate verification.");
            SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
            sslContextBuilder.loadTrustMaterial(null, new TrustStrategy() {
                @Override
                public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    return true;
                }
            });

            httpClientBuilder.setSSLHostnameVerifier(new NoopHostnameVerifier());
            httpClientBuilder.setSSLContext(sslContextBuilder.build());
        }
        if(options.containsKey("proxySettings") && Boolean.parseBoolean(options.get("proxySettings").toString())){
        	HttpHost proxy = new HttpHost(options.get("proxyIP").toString(), Integer.valueOf((String)options.get("proxyPort")), "http");
        	httpClientBuilder.setProxy(proxy);
        }

        return httpClientBuilder.build();
    }

    /**
     * Execute a single request. This will call itself if it needs to refresh an OAuth token.
     *
     * @param options All of the options provided to the plugin execution
     * @param request The HTTP request we're supposed to execute
     * @param attempts The attempt number
     * @throws StepException Thrown when any error occurs
     */
    protected void doRequest(Map<String, Object> options, HttpUriRequest request, Integer attempts) throws StepException {
        if(attempts > MAX_ATTEMPTS) {
            throw new StepException("Unable to complete request after maximum number of attempts.", StepFailureReason.IOFailure);
        }
        CloseableHttpResponse response = null;
        try {
            String body = null;
            response = this.getHttpClient(options).execute(request);

            //print the response content
            if(options.containsKey("printResponse") && Boolean.parseBoolean(options.get("printResponse").toString()) ||
                    options.containsKey("printResponseToFile") && Boolean.parseBoolean(options.get("printResponseToFile").toString())) {

                body = this.prettyPrint(response);

                if(Boolean.parseBoolean(options.get("printResponse").toString())) {
                    //print response
                    System.out.println(body);
                }

                if(Boolean.parseBoolean(options.get("printResponseToFile").toString())) {

                    File file = new File(options.get("file").toString());
                    BufferedWriter writer = new BufferedWriter(new FileWriter(file));
                    writer.write (body);

                    //Close writer
                    writer.close();
                }

            }

                //check response status
            if(options.containsKey("checkResponseCode") && Boolean.parseBoolean(options.get("checkResponseCode").toString())) {

                if(options.containsKey("responseCode")){
                    int responseCode = Integer.valueOf( (String) options.get("responseCode"));

                    if(response.getStatusLine().getStatusCode()!=responseCode){
                        String message = "Error, the expected response code didn't fix, the value expected was " + responseCode + " and the response code was " +  response.getStatusLine().getStatusCode();
                        throw new StepException(message, Reason.HTTPFailure);
                    }

                }

            }

                // Sometimes we may need to refresh our OAuth token.
            if(response.getStatusLine().getStatusCode() == OAuthClient.STATUS_AUTHORIZATION_REQUIRED) {
                log.debug("Warning: Got authorization required exception from " + request.getURI());

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
                        request.setHeader("Authorization", "Bearer " + accessToken);

                        log.trace("Authentication header set to Bearer " + accessToken);

                        this.doRequest(options, request, attempts + 1);
                    } else {
                        throw new StepException("Remote URL requires authentication.", StepFailureReason.ConfigurationFailure);
                    }
                } else {
                    throw new StepException("Remote URL requires authentication.", StepFailureReason.ConfigurationFailure);
                }
            } else if(response.getStatusLine().getStatusCode() >= 400) {
                String message = "Error when sending request";

                if(response.getStatusLine().getReasonPhrase().length() > 0) {
                    message += ": " + response.getStatusLine().getReasonPhrase();
                } else {
                    message += ": " + Integer.toString(response.getStatusLine().getStatusCode()) + " Error";
                }

                if(body == null){
                    body = EntityUtils.toString(response.getEntity());
                }

                if(body.length() > 0) {
                    message += ": " + body;
                }

                throw new StepException(message, Reason.HTTPFailure);
            }
        } catch (IOException e) {
            StepException ese = new StepException("Error when sending request: " + e.getMessage(), Reason.HTTPFailure);
            ese.initCause(e);
            throw ese;
        } catch (GeneralSecurityException se) {
            StepException sse = new StepException("Error when sending request: " + se.getMessage(), Reason.HTTPFailure);
            se.initCause(se);
            throw sse;
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public void executeStep(PluginStepContext pluginStepContext, Map<String, Object> options) throws StepException {
        String authHeader = null;

        // Parse out the options
        String remoteUrl = options.containsKey("remoteUrl") ? options.get("remoteUrl").toString() : null;
        String method = options.containsKey("method") ? options.get("method").toString() : null;
        String authentication = options.containsKey("authentication") ? options.get("authentication").toString() : AUTH_NONE;
        Integer timeout = options.containsKey("timeout") ? Integer.parseInt(options.get("timeout").toString()) : DEFAULT_TIMEOUT;
        String headers = options.containsKey("headers") ? options.get("headers").toString() : null;
        String body = options.containsKey("body") ? options.get("body").toString() : null;

        if(remoteUrl == null || method == null) {
            throw new StepException("Remote URL and Method are required.", StepFailureReason.ConfigurationFailure);
        }

        //Use options in remote URL
        if (null != remoteUrl && remoteUrl.contains("${")) {
            remoteUrl = DataContextUtils.replaceDataReferences(remoteUrl, pluginStepContext.getDataContext());
        }

        //Use options in body
        if (null != body && body.contains("${")) {
            body = DataContextUtils.replaceDataReferences(body, pluginStepContext.getDataContext());
        }

        //moving the password to the key storage
        String password=null;

        if(options.containsKey("password") ){
            String passwordRaw = options.containsKey("password") ? options.get("password").toString() : null;

            //to avid the test error add a try-catch
            //if it didn't find the key path, it will use the password directly
            try {
                ResourceMeta contents = pluginStepContext.getExecutionContext().getStorageTree().getResource(passwordRaw).getContents();

                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

                contents.writeContent(byteArrayOutputStream);

                password = new String(byteArrayOutputStream.toByteArray());
            } catch (Exception e) {
                password=null;
            }

            if(password==null){
                password=passwordRaw;
            }

        }

        if(authentication.equals(AUTH_BASIC)) {
            // Setup the authentication header for BASIC
            String username = options.containsKey("username") ? options.get("username").toString() : null;

            if(username == null || password == null) {
                throw new StepException("Username and password not provided for BASIC Authentication",
                        StepFailureReason.ConfigurationFailure);
            }

            authHeader = username + ":" + password;

            //As per RFC2617 the Basic Authentication standard has to send the credentials Base64 encoded.
            authHeader = "Basic " + com.dtolabs.rundeck.core.utils.Base64.encode(authHeader);
        } else if (authentication.equals(AUTH_OAUTH2)) {
            // Get an OAuth token and setup the auth header for OAuth
            String tokenEndpoint = options.containsKey("oauthTokenEndpoint") ? options.get("oauthTokenEndpoint").toString() : null;
            String validateEndpoint = options.containsKey("oauthValidateEndpoint") ? options.get("oauthValidateEndpoint").toString() : null;
            String clientId = options.containsKey("username") ? options.get("username").toString() : null;
            String clientSecret = password;


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
        RequestBuilder request = RequestBuilder.create(method)
                .setUri(remoteUrl)
                .setConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(timeout)
                        .setConnectTimeout(timeout)
                        .setSocketTimeout(timeout)
                        .build());

        log.debug("Creating HTTP " + request.getMethod() + " request to " + request.getUri());

        if(authHeader != null) {
            log.trace("Authentication header set to " + authHeader);
            request.setHeader("Authorization", authHeader);
        }

        //add custom headers, it could be json or yml
        if(headers !=null){

            //checking json
            Gson gson = new Gson();
            Map<String,String> map = new HashMap<>();

            try {
                map = (Map<String,String>) gson.fromJson(headers, map.getClass());
            } catch (Exception e) {
                map = null;
            }

            //checking yml
            if(map == null) {
                map = new HashMap<>();
                Object object = null;
                try {
                    YamlReader reader = new YamlReader(headers);
                    object = reader.read();
                    map = (Map<String,String>) object;
                } catch (Exception e) {
                    map = null;
                }
            }

            if(map == null){
                System.err.print("Error parsing the headers");
            }else{
                for (Map.Entry<String, String> entry : map.entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();

                    request.setHeader(key, value);
                }
            }
        }

        //send body
        if(body !=null){
            HttpEntity entity = null;
            try {
                entity = new ByteArrayEntity(body.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            request.setEntity(entity);
        }

        this.doRequest(options, request.build(), 1);
    }


    private StringBuffer getPageContent(HttpResponse response) {

        BufferedReader rd = null;
        HttpEntity reponseEntity = response.getEntity();
        StringBuffer result = new StringBuffer();

        if ( reponseEntity != null ) {
            try {
                rd = new BufferedReader(new InputStreamReader(reponseEntity.getContent()));
                String line = "";
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                    result.append(System.getProperty("line.separator"));
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (rd != null) {
                    try {
                        rd.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        return result;
    }

    //print response
    public String prettyPrint(HttpResponse response){

        HttpEntity entity = response.getEntity();
        ContentType contentType;
        String mimeType="";
        if (entity != null) {
            contentType = ContentType.get(entity);

            if(contentType!=null) {
                mimeType = contentType.getMimeType();
            }
        }

        String outputWithoutFormat=getPageContent(response).toString();

        String output = "";

        if(mimeType.contains(JSON_FORMAT) || mimeType.contains(XML_FORMAT)) {

            if (mimeType.contains(JSON_FORMAT)) {
                output = new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(outputWithoutFormat));
            }

            if (mimeType.contains(XML_FORMAT)) {
                StringWriter sw;

                try {
                    final OutputFormat format = OutputFormat.createPrettyPrint();
                    final org.dom4j.Document document = DocumentHelper.parseText(outputWithoutFormat);
                    sw = new StringWriter();
                    final XMLWriter writer = new XMLWriter(sw, format);
                    writer.write(document);
                }
                catch (Exception e) {
                    throw new RuntimeException("Error pretty printing xml:\n" + outputWithoutFormat, e);
                }

                output = sw.toString();
            }
        }else{
            output=outputWithoutFormat;
        }

        return output;
    }


}
