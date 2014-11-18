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
package com.guestful.jaxrs.security.cookie.auth;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.*;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import java.io.IOException;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class CookieAuthFeature implements Feature, DynamicFeature {

    private final Options options;

    public CookieAuthFeature(Options options) {
        this.options = options;
    }

    @Override
    public boolean configure(FeatureContext context) {
        return true;
    }

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {

    }

    /**
     * @author Mathieu Carbou (mathieu.carbou@gmail.com)
     */
    @Priority(Priorities.AUTHENTICATION)
    class CookieAuthFilter implements ContainerRequestFilter, ContainerResponseFilter {
        @Override
        public void filter(ContainerRequestContext requestContext) throws IOException {
        }

        @Override
        public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {

        }
    }

}
