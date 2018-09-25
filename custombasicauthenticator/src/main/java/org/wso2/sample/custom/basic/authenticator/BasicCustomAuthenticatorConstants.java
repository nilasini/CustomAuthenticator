package org.wso2.sample.custom.basic.authenticator;

public abstract class BasicCustomAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "CustomBasicAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "custombasic";
    public static final String USER_NAME = "username";
    public static final String PASSWORD = "password";
    public static final String FAILED_USERNAME = "&failedUsername=";
    public static final String ERROR_CODE = "&errorCode=";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";
    public static final String UTF_8 = "UTF-8";
    public static final String USER_NAME_PARAM = "&username=";
    public static final String TENANT_DOMAIN_PARAM = "&tenantdomain=";
    public static final String CONFIRMATION_PARAM = "&confirmation=";

    private BasicCustomAuthenticatorConstants() {
    }
}
