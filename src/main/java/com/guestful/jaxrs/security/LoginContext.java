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
package com.guestful.jaxrs.security;

import com.guestful.jaxrs.security.session.Session;

import javax.ws.rs.container.ContainerRequestContext;
import java.security.Principal;
import java.util.Map;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public interface LoginContext {

    Session getSession(boolean create);

    Principal getPrincipal();

    ContainerRequestContext getRequest();

    String getOrigin();

    String getUserAgent();

    Map<String, Object> getAttributes();

    default Session getSession() {
        return getSession(true);
    }

}
