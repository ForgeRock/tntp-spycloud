<!--
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
 * Copyright 2019 ForgeRock AS.
-->
# Spycloud Auth Nodes

An authentication node for ForgeRock's AM Platform 7.5.0 and ForgeRock Identity Cloud which integrates the Spycloud service with AM.

## Usage

To deploy these nodes, download the jar from the releases tab on github
[here](https://github.com/ForgeRock/tntp-spycloud/releases). Next, copy the jar into the
../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed. Restart the web container to pick up the
new node. The node will then appear in the authentication trees components palette.

If you'd like to build the integration from source, the code in this repository has binary dependencies that live in
the ForgeRock maven repository. Maven can be configured to authenticate to this repository by following the
following [ForgeRock Knowledge Base Article](https://backstage.forgerock.com/knowledge/kb/article/a74096897).

### SpyCloud node configuration
This node calls the SpyCloud service to determine of a password has been compromised for that username or email.
* **API URL** - The API URL for spycloud API
* **API Key** - The API key for spycloud API
* **Severity** - Severity to filter on
* **Username or Email** - Determine if the node should be used to check usernames or emails


[forgerock_platform]: https://www.forgerock.com/platform/  
