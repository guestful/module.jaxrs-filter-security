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
package com.guestful.jaxrs.security.session;

/**
 * date 2014-05-26
 *
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class SessionConfiguration {

    private int maxAge = 60;
    private String cookieName;
    private String cookiePath;
    private String cookieDomain;
    private boolean checkOrigin;
    private boolean checkUserAgent;

    public boolean isCheckUserAgent() {
        return checkUserAgent;
    }

    public SessionConfiguration setCheckUserAgent(boolean checkUserAgent) {
        this.checkUserAgent = checkUserAgent;
        return this;
    }

    public boolean isCheckOrigin() {
        return checkOrigin;
    }

    public SessionConfiguration setCheckOrigin(boolean checkOrigin) {
        this.checkOrigin = checkOrigin;
        return this;
    }

    public int getMaxAge() {
        return maxAge;
    }

    public SessionConfiguration setMaxAge(int maxAge) {
        this.maxAge = maxAge;
        return this;
    }

    public String getCookieName() {
        return cookieName;
    }

    public SessionConfiguration setCookieName(String cookieName) {
        this.cookieName = cookieName;
        return this;
    }

    public String getCookiePath() {
        return cookiePath;
    }

    public SessionConfiguration setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
        return this;
    }

    public String getCookieDomain() {
        return cookieDomain;
    }

    public SessionConfiguration setCookieDomain(String cookieDomain) {
        this.cookieDomain = cookieDomain;
        return this;
    }

}
