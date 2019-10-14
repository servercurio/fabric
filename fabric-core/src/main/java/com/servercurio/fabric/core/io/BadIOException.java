/*
 * Copyright 2019 Server Curio
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.servercurio.fabric.core.io;

import java.io.IOException;

public class BadIOException extends IOException {
    public BadIOException() {
    }

    public BadIOException(final String message) {
        super(message);
    }

    public BadIOException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public BadIOException(final Throwable cause) {
        super(cause);
    }
}
