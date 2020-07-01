/*
 * Copyright 2019-2020 Server Curio
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

package com.servercurio.fabric.lang;

/**
 * Provides convenient access to commonly used constant values. The values are frequently hardcoded or repeatedly
 * defined in classes. This implementation provides a convenient way to reuse these constants.
 */
public final class Constants {

    /**
     * Private default constructor to prevent instantiation.
     */
    private Constants() {

    }

    public static final class Comparable {

        public static final int LESS_THAN = -1;
        public static final int EQUALS = 0;
        public static final int GREATER_THAN = 1;

        /**
         * Private default constructor to prevent instantiation.
         */
        private Comparable() {

        }

    }

    public static final class Strings {

        public static final String EMPTY = "";
        public static final String SPACE = " ";

        public static final String HYPHEN = "-";
        public static final String UNDERSCORE = "_";
        public static final String PERIOD = ".";
        public static final String COMMA = ",";
        public static final String SEMICOLON = ";";
        public static final String COLON = ":";
        public static final String SINGLE_QUOTE = "'";
        public static final String DOUBLE_QUOTE = "\"";
        public static final String EXCLAMATION_MARK = "!";
        public static final String QUESTION_MARK = "?";
        public static final String FORWARD_SLASH = "/";
        public static final String BACK_SLASH = "\\";
        public static final String PIPE = "|";
        public static final String TILDE = "~";
        public static final String GRAVE = "`";

        public static final String POUND_SIGN = "#";
        public static final String DOLLAR_SIGN = "$";
        public static final String PLUS_SIGN = "+";
        public static final String AT_SIGN = "@";
        public static final String AMPERSAND = "&";
        public static final String PERCENT = "%";
        public static final String CARET = "^";
        public static final String ASTERISK = "*";
        public static final String SECTION = "§";
        public static final String COPYRIGHT = "©";
        public static final String TRADEMARK = "™";
        public static final String REGISTERED = "®";
        public static final String CENT = "¢";
        public static final String POUNDS = "£";
        public static final String ELLIPSIS = "…";
        public static final String PER_MILL_SIGN = "˜‰";
        public static final String DAGGER = "†";
        public static final String DOUBLE_DAGGER = "‡";
        public static final String BULLET = "•";

        public static final String OPEN_BRACKET = "[";
        public static final String CLOSE_BRACKET = "]";
        public static final String OPEN_BRACE = "{";
        public static final String CLOSE_BRACE = "}";
        public static final String OPEN_PARENTHESIS = "(";
        public static final String CLOSE_PARENTHESIS = ")";

        public static final String EQUAL = "=";
        public static final String LESS_THAN = "<";
        public static final String GREATER_THAN = ">";


        /**
         * Private default constructor to prevent instantiation.
         */
        private Strings() {
        }
    }
}
