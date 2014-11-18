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

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class Options {

    private int maxAge = 60;
    private String name = "cookie";
    private String path = "/";
    private String domain;

    public int getMaxAge() {
        return maxAge;
    }

    public Options setMaxAge(int maxAge) {
        this.maxAge = maxAge;
        return this;
    }

    public String getName() {
        return name;
    }

    public Options setName(String name) {
        this.name = name;
        return this;
    }

    public String getPath() {
        return path;
    }

    public Options setPath(String path) {
        this.path = path;
        return this;
    }

    public String getDomain() {
        return domain;
    }

    public Options setDomain(String domain) {
        this.domain = domain;
        return this;
    }

}
