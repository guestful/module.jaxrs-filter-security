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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;

/**
 * @author Mathieu Carbou (mathieu.carbou@gmail.com)
 */
public class SessionConfigurations {

    private final Map<String, SessionConfiguration> configs = new HashMap<>();

    public SessionConfigurations addDefault(SessionConfiguration config) {
        configs.put("", config);
        return this;
    }

    public SessionConfigurations add(String system, SessionConfiguration config) {
        configs.put(Objects.requireNonNull(system, "System cannot be null"), config);
        return this;
    }

    public SessionConfiguration getConfiguration(String system) {
        SessionConfiguration config = configs.get(Objects.requireNonNull(system, "System cannot be null"));
        if (config == null) {
            throw new IllegalArgumentException("SessionConfigurations not found for system '" + system + "'.");
        }
        return config;
    }

    public void forEach(BiConsumer<String, SessionConfiguration> config) {
        for (Map.Entry<String, SessionConfiguration> entry : configs.entrySet()) {
            config.accept(entry.getKey(), entry.getValue());
        }
    }
}
