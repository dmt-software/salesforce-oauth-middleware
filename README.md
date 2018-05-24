# Salesforce-OAuth-Middleware

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

$stack = new HandlerStack();
$stack->setHandler(new CurlHandler());
$stack->push(Middleware::mapRequest(
    new AuthorizationMiddleware(
        new SalesforceAuthorization($oAuthProvider, 'YourUsername', 'YourPasswordAmdSecret')
    )
));
 
$client = new Client([
    'handler' => $stack
]);
 
// request will be authorized and routed to your client (sub)domain according to the instance_url received from OAuth
$response = $client->get('https://salesforce.com/services/data/v26.0/sobjects/Account');
```

## Cache

@TODO