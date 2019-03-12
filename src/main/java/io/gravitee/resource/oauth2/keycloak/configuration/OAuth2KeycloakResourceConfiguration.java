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
package io.gravitee.resource.oauth2.keycloak.configuration;

import io.gravitee.resource.api.ResourceConfiguration;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2KeycloakResourceConfiguration implements ResourceConfiguration {

    private String keycloakConfiguration;
    private boolean validateTokenLocally;
    private String userClaim;

    public String getKeycloakConfiguration() {
        return keycloakConfiguration;
    }

    public void setKeycloakConfiguration(String keycloakConfiguration) {
        this.keycloakConfiguration = keycloakConfiguration;
    }

    public boolean isValidateTokenLocally() {
        return validateTokenLocally;
    }

    public void setValidateTokenLocally(boolean validateTokenLocally) {
        this.validateTokenLocally = validateTokenLocally;
    }

    public String getUserClaim() {
        return userClaim;
    }

    public void setUserClaim(String userClaim) {
        this.userClaim = userClaim;
    }
}
