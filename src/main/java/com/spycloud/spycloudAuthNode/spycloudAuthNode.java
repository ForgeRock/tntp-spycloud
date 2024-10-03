/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2023 ForgeRock AS.
 */


package com.spycloud.spycloudAuthNode;

import java.io.*;
import java.net.HttpURLConnection;
import java.util.*;

import org.apache.commons.lang.RandomStringUtils;
import org.forgerock.openam.auth.node.api.*;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;
import org.forgerock.util.i18n.PreferredLocales;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.net.URI;
import org.json.JSONObject;
import org.json.JSONArray;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = spycloudAuthNode.OutcomeProvider.class,
               configClass      = spycloudAuthNode.Config.class)
public class spycloudAuthNode extends AbstractDecisionNode {

    private final Pattern DN_PATTERN = Pattern.compile("^[a-zA-Z0-9]=([^,]+),");
    private final Logger logger = LoggerFactory.getLogger(spycloudAuthNode.class);
    private final Config config;
    private final Realm realm;
    private String username = null;
    private String loggerPrefix = "[SpyCloud]";
   

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The header name for zero-page login that will contain the identity's username.
         */
        
        /**
         * The header name for zero-page login that will contain the identity's password.
         */
        @Attribute(order = 200)
        default String apiUrl() {
            return "https://api.spycloud.io/sp-v2/breach/data/emails/";
        }

        /**
         * The group name (or fully-qualified unique identifier) for the group that the identity must be in.
         */
        @Attribute(order = 300)
        default String apiKey() {
            return "";
        }

        @Attribute(order = 400)
        default String severity() {
            return "25";
        }

        @Attribute(order = 500)
        default UsernameOrEmail usernameOrEmail() {
            return UsernameOrEmail.email;
        }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     */
    @Inject
    public spycloudAuthNode(@Assisted Config config, @Assisted Realm realm) {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        try {

            NodeState ns = context.getStateFor(this);
            String salt = RandomStringUtils.randomAlphanumeric(17).toUpperCase();
            HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(60)).build();
            HttpRequest.Builder requestBuilder;

            requestBuilder = HttpRequest.newBuilder().GET();

            requestBuilder.header("X-API-KEY", config.apiKey());
            requestBuilder.header("accept", "application/json");

            String identifier = null;
            switch (config.usernameOrEmail()) {
                case email: {
                    if (ns.get("objectAttributes") != null && ns.get("objectAttributes").get("mail") != null) {
                        identifier = ns.get("objectAttributes").get("mail").asString();
                    }
                    break;
                }
                case username: {
                    if (ns.get("username") != null) {
                        identifier = ns.get("username").asString();
                    }

                }
                break;
            }
            if (identifier == null) {
                logger.error(loggerPrefix + "No identifier found");
                return Action.goTo("Error").build();

            }

            String url = config.apiUrl() + identifier +"?severity="+config.severity();
            HttpRequest request = requestBuilder.uri(URI.create(url)).timeout(Duration.ofSeconds(60)).build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            JSONObject jo = new JSONObject(response.body());
            JSONArray arr = jo.getJSONArray("results");
            String password = ns.get("password").asString();

            for (int i = 0 ; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                if(obj.has("password_type")) {
                    String password_type = obj.getString("password_type");
                    if (password_type.equals("plaintext")) {

                        String pass = obj.getString("password");
                        logger.error(pass);
                        logger.error(password);
                        if (pass.equals(password)) {
                            return Action.goTo("Compromised").build();
                        }
                    }
                }
            }
            return Action.goTo("Not Compromised").build();
            
        } catch(Exception ex) { 
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            logger.error(loggerPrefix + "Response body: " + response.body());
            context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
            context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
            return Action.goTo("Error").build();

        }
    }

    public static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        /**
         * Outcomes Ids for this node.
         */
        
         static final String SUCCESS_OUTCOME = "Not Compromised";
    static final String ERROR_OUTCOME = "Error";
    static final String FAILURE_OUTCOME = "Compromised";
        private static final String BUNDLE = spycloudAuthNode.class.getName();

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());

            List<Outcome> results = new ArrayList<>(
                    Arrays.asList(
                            new Outcome(SUCCESS_OUTCOME, SUCCESS_OUTCOME)
                    )
            );
            results.add(new Outcome(FAILURE_OUTCOME, FAILURE_OUTCOME));
            results.add(new Outcome(ERROR_OUTCOME, ERROR_OUTCOME));

            return Collections.unmodifiableList(results);
        }
    }

    public enum UsernameOrEmail {
        username, email
    }

//
//    @Override
//    public InputState[] getInputs() {
//        return new InputState[] {
//                new InputState("username", false),
//                new InputState("password", false)
//        };
//    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[] {
                new OutputState("username", Map.of("true", true, "false", false)),
                new OutputState("password", Map.of("true", true, "false", false))
        };
    }
}
