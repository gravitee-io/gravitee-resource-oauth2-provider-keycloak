/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.utils.UUID;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.node.api.Node;
import io.gravitee.node.api.utils.NodeUtils;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.oauth2.keycloak.configuration.OAuth2KeycloakResourceConfiguration;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.http.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2KeycloakResource extends OAuth2Resource<OAuth2KeycloakResourceConfiguration> implements ApplicationContextAware {

    private final Logger logger = LoggerFactory.getLogger(OAuth2KeycloakResource.class);

    private static final String KEYCLOAK_INTROSPECTION_ENDPOINT = "/protocol/openid-connect/token/introspect";
    private static final String KEYCLOAK_USERINFO_ENDPOINT = "/protocol/openid-connect/userinfo";

    private static final String HTTPS_SCHEME = "https";

    private static final String AUTHORIZATION_HEADER_BASIC_SCHEME = "Basic ";
    private static final String AUTHORIZATION_HEADER_BEARER_SCHEME = "Bearer ";
    private static final char AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR = ':';

    private ApplicationContext applicationContext;

    private final Map<Thread, HttpClient> httpClients = new ConcurrentHashMap<>();

    private HttpClientOptions httpClientOptions;

    private Vertx vertx;

    private String introspectionEndpointURI;
    private String introspectionEndpointAuthorization;
    private String userInfoEndpointURI;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String realmUrl;
    private KeycloakDeployment keycloakDeployment;
    private boolean checkTokenLocally;

    private String userAgent;

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        logger.info("Starting a Keycloak Adapter resource");

        checkTokenLocally = configuration().isValidateTokenLocally();
        InputStream configStream = new ByteArrayInputStream(configuration().getKeycloakConfiguration().getBytes(StandardCharsets.UTF_8));
        AdapterConfig adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(configStream);
        keycloakDeployment = KeycloakDeploymentBuilder.build(adapterConfig);

        realmUrl = adapterConfig.getAuthServerUrl() + "/realms/" + adapterConfig.getRealm();

        URI introspectionUri = URI.create(realmUrl);

        int authorizationServerPort = introspectionUri.getPort() != -1
            ? introspectionUri.getPort()
            : (HTTPS_SCHEME.equals(introspectionUri.getScheme()) ? 443 : 80);
        String authorizationServerHost = introspectionUri.getHost();

        httpClientOptions = new HttpClientOptions().setDefaultPort(authorizationServerPort).setDefaultHost(authorizationServerHost);

        // Use SSL connection if authorization schema is set to HTTPS
        if (HTTPS_SCHEME.equalsIgnoreCase(introspectionUri.getScheme())) {
            httpClientOptions.setSsl(true).setVerifyHost(configuration().isVerifyHost()).setTrustAll(configuration().isTrustAll());
        }

        introspectionEndpointAuthorization =
            AUTHORIZATION_HEADER_BASIC_SCHEME +
            Base64
                .getEncoder()
                .encodeToString(
                    (
                        adapterConfig.getResource() +
                        AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR +
                        adapterConfig.getCredentials().get("secret")
                    ).getBytes()
                );

        // Prepare userinfo endpoint calls
        userInfoEndpointURI = introspectionUri.getPath() + KEYCLOAK_USERINFO_ENDPOINT;

        // Prepare introspection endpoint calls
        introspectionEndpointURI = introspectionUri.getPath() + KEYCLOAK_INTROSPECTION_ENDPOINT;
        userAgent = NodeUtils.userAgent(applicationContext.getBean(Node.class));
        vertx = applicationContext.getBean(Vertx.class);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();
        httpClients
            .values()
            .forEach(httpClient -> {
                try {
                    httpClient.close();
                } catch (IllegalStateException ise) {
                    logger.warn(ise.getMessage());
                }
            });
    }

    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        if (checkTokenLocally) {
            try {
                AccessToken token = AdapterTokenVerifier.verifyToken(accessToken, keycloakDeployment);
                // Not optimal
                ObjectNode tokenMetadata = JsonSerialization.createObjectNode(token);
                tokenMetadata.put("client_id", token.getIssuedFor());
                tokenMetadata.put("username", token.getPreferredUsername());
                responseHandler.handle(new OAuth2Response(true, MAPPER.writeValueAsString(tokenMetadata)));
            } catch (VerificationException ve) {
                logger.error("Unable to verify access token", ve);
                responseHandler.handle(new OAuth2Response(false, "{\"error\": \"access_denied\"}"));
            } catch (IOException e) {
                logger.error("Unable to transform access token", e);
            }
        } else {
            HttpClient httpClient = httpClients.computeIfAbsent(
                Thread.currentThread(),
                context -> vertx.createHttpClient(httpClientOptions)
            );

            logger.debug("Introspect access token by requesting {}", introspectionEndpointURI);

            final RequestOptions reqOptions = new RequestOptions()
                .setMethod(HttpMethod.POST)
                .setURI(introspectionEndpointURI)
                .putHeader(HttpHeaders.USER_AGENT, userAgent)
                .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
                .putHeader(HttpHeaders.AUTHORIZATION, introspectionEndpointAuthorization)
                .putHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON)
                .putHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

            httpClient
                .request(reqOptions)
                .onFailure(
                    new io.vertx.core.Handler<Throwable>() {
                        @Override
                        public void handle(Throwable event) {
                            logger.error("An error occurs while introspecting access token", event);
                            responseHandler.handle(new OAuth2Response(false, event.getMessage()));
                        }
                    }
                )
                .onSuccess(
                    new io.vertx.core.Handler<HttpClientRequest>() {
                        @Override
                        public void handle(HttpClientRequest request) {
                            request
                                .response(
                                    new io.vertx.core.Handler<AsyncResult<HttpClientResponse>>() {
                                        @Override
                                        public void handle(AsyncResult<HttpClientResponse> asyncResponse) {
                                            if (asyncResponse.failed()) {
                                                logger.error("An error occurs while introspecting access token", asyncResponse.cause());
                                                responseHandler.handle(new OAuth2Response(false, asyncResponse.cause().getMessage()));
                                            } else {
                                                final HttpClientResponse response = asyncResponse.result();
                                                response.bodyHandler(buffer -> {
                                                    logger.debug(
                                                        "Keycloak introspection endpoint returns a response with a {} status code",
                                                        response.statusCode()
                                                    );
                                                    String body = buffer.toString();
                                                    if (response.statusCode() == HttpStatusCode.OK_200) {
                                                        JsonNode introspectPayload = readPayload(body);
                                                        boolean active =
                                                            introspectPayload != null && introspectPayload.path("active").asBoolean(false);
                                                        if (active) {
                                                            responseHandler.handle(new OAuth2Response(true, body));
                                                        } else {
                                                            responseHandler.handle(
                                                                new OAuth2Response(false, "{\"error\": \"access_denied\"}")
                                                            );
                                                        }
                                                    } else {
                                                        responseHandler.handle(new OAuth2Response(false, body));
                                                    }
                                                });
                                            }
                                        }
                                    }
                                )
                                .exceptionHandler(
                                    new io.vertx.core.Handler<Throwable>() {
                                        @Override
                                        public void handle(Throwable event) {
                                            logger.error("An error occurs while introspecting access token", event);
                                            responseHandler.handle(new OAuth2Response(false, event.getMessage()));
                                        }
                                    }
                                )
                                .end("token=" + accessToken);
                        }
                    }
                );
        }
    }

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {
        HttpClient httpClient = httpClients.computeIfAbsent(Thread.currentThread(), context -> vertx.createHttpClient(httpClientOptions));

        logger.debug("Get userinfo from {}", userInfoEndpointURI);

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setURI(userInfoEndpointURI)
            .putHeader(HttpHeaders.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
            .putHeader(HttpHeaders.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken)
            .putHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);

        httpClient
            .request(reqOptions)
            .onFailure(
                new io.vertx.core.Handler<Throwable>() {
                    @Override
                    public void handle(Throwable event) {
                        logger.error("An error occurs while getting userinfo from access token", event);
                        responseHandler.handle(new UserInfoResponse(false, event.getMessage()));
                    }
                }
            )
            .onSuccess(
                new io.vertx.core.Handler<HttpClientRequest>() {
                    @Override
                    public void handle(HttpClientRequest request) {
                        request
                            .response(
                                new io.vertx.core.Handler<AsyncResult<HttpClientResponse>>() {
                                    @Override
                                    public void handle(AsyncResult<HttpClientResponse> asyncResponse) {
                                        if (asyncResponse.failed()) {
                                            logger.error("An error occurs while introspecting access token", asyncResponse.cause());
                                            responseHandler.handle(new UserInfoResponse(false, asyncResponse.cause().getMessage()));
                                        } else {
                                            final HttpClientResponse response = asyncResponse.result();
                                            response.bodyHandler(buffer -> {
                                                logger.debug(
                                                    "Userinfo endpoint returns a response with a {} status code",
                                                    response.statusCode()
                                                );

                                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                                    responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
                                                } else {
                                                    responseHandler.handle(new UserInfoResponse(false, buffer.toString()));
                                                }
                                            });
                                        }
                                    }
                                }
                            )
                            .exceptionHandler(
                                new io.vertx.core.Handler<Throwable>() {
                                    @Override
                                    public void handle(Throwable event) {
                                        logger.error("An error occurs while introspecting access token", event);
                                        responseHandler.handle(new UserInfoResponse(false, event.getMessage()));
                                    }
                                }
                            )
                            .end();
                    }
                }
            );
    }

    private JsonNode readPayload(String oauthPayload) {
        try {
            return MAPPER.readTree(oauthPayload);
        } catch (IOException ioe) {
            logger.error("Unable to check required scope from introspection endpoint payload: {}", oauthPayload);
            return null;
        }
    }

    @Override
    public String getUserClaim() {
        return configuration().getUserClaim();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
