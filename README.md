# Salesforce-OAuth-Middleware

[![Build Status](https://travis-ci.org/dmt-software/salesforce-oauth-middleware.svg?branch=master)](https://travis-ci.org/dmt-software/salesforce-oauth-middleware)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/dmt-software/salesforce-oauth-middleware/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/dmt-software/salesforce-oauth-middleware/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/dmt-software/salesforce-oauth-middleware/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/dmt-software/salesforce-oauth-middleware/?branch=master)

This authorization middleware uses the OAuth `grant_type` [password](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_understanding_username_password_oauth_flow.htm)
to authenticate and authorize a request to the Salesforce REST API. 

## Install
`composer require dmt-software/salesforce-oauth-middleware`

## Usage

```php
<?php
 
use DMT\Salesforce\Auth\Authorization\SalesforceAuthorization;
use DMT\Auth\AuthorizationMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Stevenmaguire\OAuth2\Client\Provider\Salesforce;
 
$oAuthProvider = new Salesforce(
     [
         'clientId'          => 'YourCustomedKey',
         'clientSecret'      => 'YourCustomerSecret',
         'redirectUri'       => 'https://localhost', // wont be visited for grant_type password
     ]
);
$authMiddleware = new AuthorizationMiddleware(
  new SalesforceAuthorization($oAuthProvider, 'YourUsername', 'YourPasswordAmdSecret')
);

$stack = new HandlerStack();
$stack->setHandler(new CurlHandler());
$stack->push(Middleware::mapRequest($authMiddleware));
 
$client = new Client([
    'handler' => $stack
]);
 
// request will be authorized and routed to your client (sub)domain according to the instance_url received from OAuth
$response = $client->get('https://salesforce.com/services/data/v26.0/sobjects/Account');
```
## Cache

To re-use an access token this middleware can be configured with a PSR-16 cache implementation.
```php
<?php
 
use DMT\Salesforce\Auth\Authorization\SalesforceAuthorization;
use DMT\Auth\AuthorizationMiddleware;
use Psr\SimpleCache\CacheInterface;
use Stevenmaguire\OAuth2\Client\Provider\Salesforce;
 
/** @var Salesforce $oAuthProvider */
/** @var CacheInterface $dataCache */
$authMiddleware = new AuthorizationMiddleware(
    new SalesforceAuthorization($oAuthProvider, 'YourUsername', 'YourPasswordAmdSecret', $dataCache)
);
``` 
NOTE: Currently Salesforce does not provide an expiration time or refresh token when `grant_type` password is used.
Cached access tokens will be recycled every hour (when handled by this middleware). 
This might change later to better suit implementations (I'm open for suggestions).
