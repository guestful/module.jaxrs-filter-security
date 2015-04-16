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
package com.guestful.jaxrs.security.realm;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

/**
 * date 2014-05-23
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class Account {

    private final Principal principal;
    private final Object credentials;
    private final Collection<String> roles = new HashSet<>();
    private final Collection<String> permissions = new HashSet<>();
    private boolean locked;

    public Account(String principalName) {
        this(new StringPrincipal(principalName));
    }

    public Account(Principal principal) {
        this(principal, null);
    }

    public Account(String principalName, Object credentials) {
        this(new StringPrincipal(principalName), credentials);
    }

    public Account(Principal principal, Object credentials) {
        this.principal = principal;
        this.credentials = credentials;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public Principal getPrincipal() {
        return principal;
    }

    public Object getCredentials() {
        return credentials;
    }

    public boolean isLocked() {
        return locked;
    }

    public Collection<String> getRoles() {
        return roles;
    }

    public Collection<String> getPermissions() {
        return permissions;
    }

    public void addRole(String role) {
        roles.add(role);
    }

    public void addRoles(String... roles) {
        this.roles.addAll(Arrays.asList(roles));
    }

    public void addRoles(Collection<String> roles) {
        this.roles.addAll(roles);
    }

    public void addPermission(String permission) {
        permissions.add(permission);
    }

    public void addPermissions(String... permissions) {
        this.permissions.addAll(Arrays.asList(permissions));
    }

    public void addPermissions(Collection<String> permissions) {
        this.permissions.addAll(permissions);
    }

    @Override
    public String toString() {
        return getPrincipal().toString();
    }
}
