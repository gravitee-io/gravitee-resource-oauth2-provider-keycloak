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
package io.gravitee.resource.oauth2.keycloak.adapters;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.util.SystemPropertiesJsonParserFactory;

import java.io.IOException;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class KeycloakDeploymentBuilder {

    public static AdapterConfig loadAdapterConfig(String content) {
        ObjectMapper mapper = new ObjectMapper(new SystemPropertiesJsonParserFactory());
        mapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        AdapterConfig adapterConfig;
        try {
            adapterConfig = mapper.readValue(content, AdapterConfig.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return adapterConfig;
    }
}
