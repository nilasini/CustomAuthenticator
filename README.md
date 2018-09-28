This CustomAuthenticator will include user store precedence during the login using Wso2-IS
Follow the below steps to tryout the scenario

1. Build the project

2. Copy org.wso2.sample.custom.basic.authenticator-1.0-SNAPSHOT.jar file to <IS_HOME>/repository/Components/dropins folder

3. Add the following property in application-authentication.xml under the tag AuthenticatorConfigs. Here, the name is the custom sample authenticator's name, UserStoresPrecedence is the user stores order. The values for UserStoresPrecedence should be the secondary user store domain names.
`<AuthenticatorConfig name="CustomBasicAuthenticator" enabled="true"> <Parameter name="UserStoresPrecedence">Secondary,Third</Parameter> </AuthenticatorConfig>`

 Add an alias under AuthenticatorNameMappings as below.
`<AuthenticatorNameMapping name="CustomBasicAuthenticator" alias="custombasic" />`

4. Restart the server
5. Add user stores with domain name as Secondary. Third
6. Add users to the user stores
7. Login through the user without specifying the domain, then the user will be authenticated according to the user store precedence configured through application-authentication.xml
