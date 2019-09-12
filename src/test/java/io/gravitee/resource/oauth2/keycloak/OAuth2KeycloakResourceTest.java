/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.keycloak;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.vertx.core.Vertx;
import org.apache.http.HttpHeaders;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationContext;
import io.gravitee.resource.oauth2.keycloak.configuration.OAuth2KeycloakResourceConfiguration;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.Assert.*;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2KeycloakResourceTest {

    private static final String KEYCLOAK_USERINFO_URI =
            "/auth/realms/Gravitee/protocol/openid-connect/userinfo";
    private static final String KEYCLOAK_INROSPECT_TOKEN_URI =
            "/auth/realms/Gravitee/protocol/openid-connect/token/introspect";

    private static final String ADAPTER_CONFIG = "{\n" +
            "  \"realm\": \"Gravitee\",\n" +
            "  \"auth-server-url\": \"http://localhost:%s/auth\",\n" +
            "  \"ssl-required\": \"all\",\n" +
            "  \"resource\": \"gravitee-gateway\",\n" +
            "  \"credentials\": {\n" +
            "    \"secret\": \"xxx\"\n" +
            "  },\n" +
            "  \"verify-token-audience\": true,\n" +
            "  \"confidential-port\": 0\n" +
            "}";

    private static final String ACCESS_DENIDED_RESPONSE = "{\"error\": \"access_denied\"}";

    private static final String EXPECTED_USERINFO_RESPONSE = "{" +
            "\"sub\": \"248289761001\", " +
            "\"name\": \"Jane Doe\", " +
            "\"given_name\": \"Jane\"" +
            "}";

    private static final String EXPECTED_INROSPECTION_ACTIVE_RESPONSE = "{\"active\": true}";
    private static final String EXPECTED_INROSPECTION_NONACTIVE_RESPONSE = "{\"active\": false}";


    private static class TestResponseHandler<T> implements Handler<T> {

        private CountDownLatch lock;
        private T response;

        public TestResponseHandler(CountDownLatch lock) {
            this.lock = lock;
        }

        public T getResponse() {
            return response;
        }

        @Override
        public void handle(T response) {
            this.response = response;
            lock.countDown();
        }
    }

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private OAuth2KeycloakResourceConfiguration configuration;

    @InjectMocks
    private OAuth2KeycloakResource resource;

    @Before
    public void init() {
        initMocks(this);
        Mockito.when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());
    }

    @Test
    public void shouldValidateAccessTokenViaIntrospectSuccessfully() throws Exception {
        Mockito.when(configuration.getKeycloakConfiguration())
                .thenReturn(String.format(ADAPTER_CONFIG, wireMockRule.port()));

        Mockito.when(configuration.isValidateTokenLocally())
                .thenReturn(false);

        stubFor(post(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(EXPECTED_INROSPECTION_ACTIVE_RESPONSE)));

        resource.doStart();

        final CountDownLatch lock = new CountDownLatch(1);
        final TestResponseHandler<OAuth2Response> handler = new TestResponseHandler<>(lock);

        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        resource.introspect(accessToken, handler);
        assertTrue(lock.await(10000, TimeUnit.MILLISECONDS));

        assertTrue(handler.getResponse().isSuccess());
        assertEquals(EXPECTED_INROSPECTION_ACTIVE_RESPONSE, handler.getResponse().getPayload());

        verify(postRequestedFor(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .withHeader(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token="+accessToken)));
    }

    @Test
    public void shouldValidateAccessTokenViaIntrospectFailure401() throws Exception {
        Mockito.when(configuration.getKeycloakConfiguration())
                .thenReturn(String.format(ADAPTER_CONFIG, wireMockRule.port()));

        Mockito.when(configuration.isValidateTokenLocally())
                .thenReturn(false);

        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .willReturn(aResponse()
                        .withStatus(401)));

        final CountDownLatch lock = new CountDownLatch(1);

        resource.doStart();

        final TestResponseHandler<OAuth2Response> handler = new TestResponseHandler<>(lock);

        resource.introspect(accessToken, handler);
        assertTrue(lock.await(10000, TimeUnit.MILLISECONDS));

        assertFalse(handler.getResponse().isSuccess());
        assertTrue(handler.getResponse().getPayload().isEmpty());

        verify(postRequestedFor(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .withHeader(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token="+accessToken)));
    }

    @Test
    public void shouldValidateAccessTokenViaIntrospectFailureInactive() throws Exception {
        Mockito.when(configuration.getKeycloakConfiguration())
                .thenReturn(String.format(ADAPTER_CONFIG, wireMockRule.port()));

        Mockito.when(configuration.isValidateTokenLocally())
                .thenReturn(false);

        stubFor(post(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(EXPECTED_INROSPECTION_NONACTIVE_RESPONSE)));

        final CountDownLatch lock = new CountDownLatch(1);

        resource.doStart();

        final TestResponseHandler<OAuth2Response> handler = new TestResponseHandler<>(lock);

        final String accessToken = "xxxx-xxxx-xxxx-xxxx";

        resource.introspect(accessToken, handler);
        assertTrue(lock.await(10000, TimeUnit.MILLISECONDS));

        assertFalse(handler.getResponse().isSuccess());
        assertEquals(ACCESS_DENIDED_RESPONSE, handler.getResponse().getPayload());

        verify(postRequestedFor(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .withHeader(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token=" + accessToken)));
    }

    @Test
    public void shouldValidateAccessTokenViaIntrospectFailureBadResponse() throws Exception {
        Mockito.when(configuration.getKeycloakConfiguration())
                .thenReturn(String.format(ADAPTER_CONFIG, wireMockRule.port()));

        Mockito.when(configuration.isValidateTokenLocally())
                .thenReturn(false);

        stubFor(post(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("")));

        final CountDownLatch lock = new CountDownLatch(1);

        resource.doStart();

        final TestResponseHandler<OAuth2Response> handler = new TestResponseHandler<>(lock);

        final String accessToken = "xxxx-xxxx-xxxx-xxxx";

        resource.introspect(accessToken, handler);
        assertTrue(lock.await(10000, TimeUnit.MILLISECONDS));

        assertFalse(handler.getResponse().isSuccess());
        assertEquals(ACCESS_DENIDED_RESPONSE, handler.getResponse().getPayload());

        verify(postRequestedFor(urlEqualTo(KEYCLOAK_INROSPECT_TOKEN_URI))
                .withHeader(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token=" + accessToken)));
    }

    @Test
    public void shouldGetUserInfo() throws Exception {
        Mockito.when(configuration.getKeycloakConfiguration())
                .thenReturn(String.format(ADAPTER_CONFIG, wireMockRule.port()));

        stubFor(get(urlEqualTo(KEYCLOAK_USERINFO_URI))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(EXPECTED_USERINFO_RESPONSE)));

        final CountDownLatch lock = new CountDownLatch(1);

        resource.doStart();

        final TestResponseHandler<UserInfoResponse> handler = new TestResponseHandler<>(lock);

        resource.userInfo("xxxx-xxxx-xxxx-xxxx", handler);
        assertTrue(lock.await(10000, TimeUnit.MILLISECONDS));

        assertTrue(handler.getResponse().isSuccess());
        assertEquals(EXPECTED_USERINFO_RESPONSE, handler.getResponse().getPayload());

        verify(getRequestedFor(urlEqualTo(KEYCLOAK_USERINFO_URI)));
    }

    @Test
    public void shouldNotGetUserInfo() throws Exception {
        Mockito.when(configuration.getKeycloakConfiguration())
                .thenReturn(String.format(ADAPTER_CONFIG, wireMockRule.port()));

        stubFor(get(urlEqualTo(KEYCLOAK_USERINFO_URI))
                .willReturn(aResponse()
                        .withStatus(401)));

        final CountDownLatch lock = new CountDownLatch(1);

        resource.doStart();

        final TestResponseHandler<UserInfoResponse> handler = new TestResponseHandler<>(lock);

        resource.userInfo("xxxx-xxxx-xxxx-xxxx", handler);
        assertTrue(lock.await(10000, TimeUnit.MILLISECONDS));

        assertFalse(handler.getResponse().isSuccess());

        verify(getRequestedFor(urlEqualTo(KEYCLOAK_USERINFO_URI)));
    }

}