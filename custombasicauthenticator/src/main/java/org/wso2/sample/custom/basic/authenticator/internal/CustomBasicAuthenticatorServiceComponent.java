/*
 * Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * 
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.custom.basic.authenticator.internal;

import org.wso2.sample.custom.basic.authenticator.CustomBasicAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * @scr.component name="application.authenticator.dbevaldev.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class CustomBasicAuthenticatorServiceComponent {

    private static final Log LOGGER = LogFactory.getLog(CustomBasicAuthenticatorServiceComponent.class);
	private static RealmService realmService;

    protected void activate(ComponentContext context) {

        try {
            CustomBasicAuthenticator customBasicAuthenticator = new CustomBasicAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();

            context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customBasicAuthenticator, props);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Custom authenticator bundle is activated");
            }
        } catch (Exception e) {
            LOGGER.fatal(" Error while activating custom authenticator ", e);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Custom authenticator bundle is deactivated");
        }
    }

	public static RealmService getRealmService() {
		return realmService;
	}

	protected void setRealmService(RealmService realmService) {
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("Setting the Realm Service");
		}
		CustomBasicAuthenticatorServiceComponent.realmService = realmService;
	}

	protected void unsetRealmService(RealmService realmService) {
		if(LOGGER.isDebugEnabled()) {
			LOGGER.debug("UnSetting the Realm Service");
		}
		CustomBasicAuthenticatorServiceComponent.realmService = null;
	}
}
