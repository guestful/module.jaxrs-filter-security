/**
 * Copyright (C) 2013 Guestful (info@guestful.com)
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
package com.guestful.jaxrs.security.filter;

import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class SecurityFeature implements Feature {
    @Override
    public boolean configure(FeatureContext context) {
        // security context setup and cleanup
        context.register(SubjectContextFilter.class);
        // authenticators
        context.register(HttpBasicAuthenticationFilter.class);
        context.register(HttpCookieAuthenticationFilter.class);
        // authc checks
        context.register(AuthenticatedFeature.class);
        // authz checks
        context.register(RolesAllowedFeature.class);
        context.register(PermissionsFeature.class);
        // session feature
        context.register(SessionFilter.class);
        context.register(SessionCookieFilter.class);
        return true;
    }
}
