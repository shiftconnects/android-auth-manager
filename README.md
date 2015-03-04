# Android Authentication Manager

This library handles much of the cruft needed in Android to interface with AccountManager. It provides a mechanism for storing a user in your app within AccountManager and automatically refreshing an OAuth2 token when necessary. It currently supports [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3) and [Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4) of RFC 6749.   

## Setup
* Add the following to your ```build.gradle``` file:
```gradle
compile('com.shiftconnects.android.auth:android-auth-manager:1.0.1')
```
* Implement ```OAuthTokenService``` which will be used to fetch OAuth tokens.
* Implement ```Crypto``` which will be used to encrypt and decrypt the *optional* refresh token. *(if you aren't supporting a refresh token you can just create a stub implementation that returns the same string)*
* Create an instance of ```AuthenticationManager``` which handles authenticating user accounts and storing them within ```AccountManager```.
* Create an instance of ```AccountAuthenticator``` which requires a ```Class``` that will be used for login. The ```Class``` must be an ```Activity``` and must also implement ```AuthenticatorActivity``` and extend ```AccountAuthenticatorActivity``` or contain the same account authenticator code that exists within ```AccountAuthenticatorActivity```. This ```Activity``` will be launched if a call to ```AuthenticationManager.authenticate()``` is made and there is no authenticated account for the account type and auth token type provided.
* Extend ```AccountAuthenticatorService``` and return your instance of ```AccountAuthenticator```. Example:
```java
public class ExampleAuthenticatorService extends AccountAuthenticatorService {

    @Override protected AccountAuthenticator getAccountAuthenticator() {
        return ExampleApplication.ACCOUNT_AUTHENTICATOR;
    }
}
```
* Create an xml file which declares your ```AccountAuthenticator``` and put it in your ```res/xml``` folder. Example:
```xml
<?xml version="1.0" encoding="utf-8"?>
<account-authenticator xmlns:android="http://schemas.android.com/apk/res/android"
                       android:accountType="Your Account Type"
                       android:label="Your Label" />
```
* Declare your ```AccountAuthenticatorService``` in your AndroidManifest.xml file. The resource should be the file you just created. Example:
```xml
<service android:name="com.shiftconnects.android.auth.example.ExampleAuthenticatorService" android:exported="false">
     <intent-filter>
          <action android:name="android.accounts.AccountAuthenticator" />
          </intent-filter>
          <meta-data android:name="android.accounts.AccountAuthenticator"
                     android:resource="@xml/authenticator" />
</service>
```

## Usage

Typical usage will be creating an "authenticated" ```Activity``` which requires an auth token in order to make a request. For this usage you will want to have your ```Activity``` implement ```AuthenticationManager.Callbacks``` as can be seen in the example activity, ```ExampleAuthenticatedActivity```. Before making a request you will want to initiate a call to ```AuthenticationManager.authenticate()``` passing the account type and auth token type you are looking for. If there is already an authenticated account, you will receive a callback in ```onAuthenticationSuccessful(String authToken)``` with the valid auth token. If not, your login activity class will be launched and the user will be required to login. Upon successful login, your authenticated activity will receive the callback to ```onAuthenticationSuccessful(String authToken)``` with the auth token and you can then make your authenticated request.

If your authentication server supports refresh tokens, ```AuthenticationManager``` will automatically refresh the expired auth token and return a valid one in the callback.

When you want to logout your user, make a call to ```AuthenticationManager.logout()``` and a call will be made to ```AuthenticationManager.Callbacks.onAuthenticationInvalidated(String invalidatedAuthToken)``` once the account has been removed and the authentication has been invalidated.

## Sample

There is sample included with this project which will demonstrate how to wire everything up and uses the Resource Owner Password Credentials Grant in order to retrieve OAuth tokens.

The sample interfaces with the [Bitly](https://bitly.com) api in order to retrieve an OAuth token and then it will use that to shorten a url with the Bitly api.

In order to test the sample you will need to create an account with Bitly and create an app at their [developer site](http://dev.bitly.com/). Once you have an app you will have a client id and client secret. You will then need to replace the following strings with your client id and client secret in ```ExampleApplication```:

```java
private static final String BITLY_CLIENT_ID = "your-bitly-client-id";
private static final String BITLY_CLIENT_SECRET = "your-bitly-client-secret";
```

## Permissions Used

The following permissions are required and used within this project for obvious reasons:

```xml
	<!-- Need internet to fetch tokens -->
    <uses-permission android:name="android.permission.INTERNET"/>

    <!-- Needed to use AccountManager -->
    <uses-permission android:name="android.permission.AUTHENTICATE_ACCOUNTS"/>
    <uses-permission android:name="android.permission.MANAGE_ACCOUNTS"/>
    <uses-permission android:name="android.permission.USE_CREDENTIALS"/>
```