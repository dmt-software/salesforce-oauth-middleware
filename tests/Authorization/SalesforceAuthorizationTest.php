<?php

namespace DMT\Test\Salesforce\Auth\Authorization;

use DMT\Salesforce\Auth\Authorization\SalesforceAuthorization;
use DMT\Test\Salesforce\Auth\Fixtures\CacheException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use Stevenmaguire\OAuth2\Client\Provider\Salesforce;
use Stevenmaguire\OAuth2\Client\Token\AccessToken;

/**
 * Class SalesforceAuthorizationTest
 *
 * @package DMT\Salesforce\Auth
 */
class SalesforceAuthorizationTest extends TestCase
{
    /**
     * @var array
     */
    protected $accessToken = [];

    /**
     * @var array
     */
    protected $cacheContainer = [];

    /**
     * Store a json token response body.
     */
    public function setUp()
    {
        $this->accessToken = [
            'instance_url' => 'https://user-3001.cloudforce.com',
            'id' => 'https://login.salesforce.com/id/00Db0000000bF1jN44/005b0000005jPFjAAM',
            'token_type' => 'Bearer',
            'issued_at' => strval(time()),
            'signature' => 'ODExMDQ5ODk5ODA=',
            'access_token' => '00Db0000000bHq1!Mu5eb70Rk_3Tc...',
        ];
        $this->accessToken['resource_owner_id'] = $this->accessToken['id'];
    }

    /**
     * Test the happy flow.
     *
     * @throws InvalidArgumentException
     */
    public function testAuthorization()
    {
        $accessToken = new AccessToken($this->accessToken);
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $request = new Request('GET', 'https://salesforce.com/services/data/v42.0/');

        $authorization = new SalesforceAuthorization($provider, 'user@org.salesforce.com', 'pass1234');
        $authRequest = $authorization->handle($request);

        static::assertEmpty($request->getHeaderLine('Authorization'));
        static::assertNotEquals($request->getUri()->getHost(), $authRequest->getUri()->getHost());
        static::assertContains($authRequest->getUri()->getHost(), $accessToken->getInstanceUrl());
        static::assertContains($accessToken->getToken(), $authRequest->getHeaderLine('Authorization'));
    }

    /**
     * Test the access token is stored in cache and re-used.
     *
     * @throws InvalidArgumentException
     * @throws \ReflectionException
     */
    public function testAuthorizationWithEmptyCache()
    {
        $accessToken = new AccessToken($this->accessToken);
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $request = new Request('GET', 'https://salesforce.com/services/data/v42.0/');

        $cache = $this->getMockedCache();
        $cache->expects(static::once())->method('has');
        $cache->expects(static::never())->method('get');
        $cache->expects(static::once())->method('set');

        $authorization = new SalesforceAuthorization($provider, 'user@org.salesforce.com', 'pass1234', $cache);
        $authRequest = $authorization->handle($request);

        static::assertEmpty($request->getHeaderLine('Authorization'));
        static::assertNotEquals($request->getUri()->getHost(), $authRequest->getUri()->getHost());
        static::assertContains($authRequest->getUri()->getHost(), $accessToken->getInstanceUrl());
        static::assertContains($accessToken->getToken(), $authRequest->getHeaderLine('Authorization'));
        static::assertSame(json_encode($accessToken), $this->cacheContainer[SalesforceAuthorization::CACHE_KEY]);
    }

    /**
     * Test access token is retrieved from cache.
     *
     * @throws \ReflectionException
     * @throws InvalidArgumentException
     */
    public function testAuthorizationFromCache()
    {
        $accessToken = new AccessToken($this->accessToken);
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $request = new Request('GET', 'https://salesforce.com/services/data/v42.0/');

        $cache = $this->getMockedCache(json_encode($accessToken));
        $cache->expects(static::once())->method('has');
        $cache->expects(static::once())->method('get');
        $cache->expects(static::never())->method('set');

        $authorization = new SalesforceAuthorization($provider, 'user@org.salesforce.com', 'pass1234', $cache);
        $authRequest = $authorization->handle($request);

        static::assertEmpty($request->getHeaderLine('Authorization'));
        static::assertNotEquals($request->getUri()->getHost(), $authRequest->getUri()->getHost());
        static::assertContains($authRequest->getUri()->getHost(), $accessToken->getInstanceUrl());
        static::assertContains($accessToken->getToken(), $authRequest->getHeaderLine('Authorization'));
        static::assertSame(json_encode($accessToken), $this->cacheContainer[SalesforceAuthorization::CACHE_KEY]);
    }

    /**
     * @dataProvider provideAuthorizationExceptions
     *
     * @expectedException \DMT\Auth\AuthorizationException
     * @expectedExceptionMessageRegExp ~Authentication failed: ~
     *
     * @param GuzzleException $exception
     * @throws InvalidArgumentException
     */
    public function testAuthorizationFailed(GuzzleException $exception)
    {
        $provider = $this->getMockedSalesforceProvider(
            new Client([
                'handler' => HandlerStack::create(new MockHandler([$exception])),
            ])
        );

        $authorization = new SalesforceAuthorization($provider, 'user@organisation.salesforce.com', 'pass1234');
        $authorization->handle(new Request('GET', 'https://salesforce.com/services/data/v42.0/'));
    }

    public function provideAuthorizationExceptions(): array
    {
        return [
            [new ConnectException("Could not connect to SF", new Request('GET', '/'))],
            [new ClientException('Missing credentials', new Request('GET', '/'), new Response(401))],
            [new ServerException('Service is unavailable', new Request('GET', '/'), new Response(500))],
        ];
    }

    /**
     * @throws InvalidArgumentException
     * @throws \ReflectionException
     */
    public function testIgnoreAndOverwriteInvalidCacheToken()
    {
        $accessToken = new AccessToken($this->accessToken);
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $request = new Request('GET', 'https://salesforce.com/services/data/v42.0/');

        $cache = $this->getMockedCache('{}');
        $cache->expects(static::once())->method('has');
        $cache->expects(static::once())->method('get');
        $cache->expects(static::once())->method('set');

        $authorization = new SalesforceAuthorization($provider, 'user', 'pass', $cache);
        $authorization->handle($request);

        static::assertSame(json_encode($accessToken), $this->cacheContainer[SalesforceAuthorization::CACHE_KEY]);
    }

    /**
     * @dataProvider provideCacheMethods
     *
     * @expectedException \Psr\SimpleCache\InvalidArgumentException
     * @expectedExceptionMessage Illegal cache key
     *
     * @param string $method
     *
     * @throws \ReflectionException
     */
    public function testCacheThrowsInvalidArgumentException(string $method = 'get')
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());

        /** @var CacheInterface|MockObject $cache */
        $cache = $this->getMockedCache();

        if ($method === 'get') {
            $cache = $this->getMockedCache('{}');
        }

        $cache->expects(static::once())
            ->method($method)
            ->willThrowException(new CacheException('Illegal cache key'));

        $authorization = new SalesforceAuthorization($provider, 'user@org.salesforce.com', 'pass1234', $cache);
        $authorization->handle(new Request('GET', 'https://localhost'));
    }

    public function provideCacheMethods(): array
    {
        return [['get'], ['set'], ['has']];
    }

    /**
     * @param Client $httpClient
     * @return Salesforce
     */
    protected function getMockedSalesforceProvider(Client $httpClient): Salesforce
    {
        $config = [
            'clientId'          => 'YourCustomedKey',
            'clientSecret'      => 'YourCustomerSecret',
            'redirectUri'       => 'https://wont-be-called-with-grant-type-password',
        ];

        return new Salesforce($config, ['httpClient' => $httpClient]);
    }

    /**
     * @return Client
     */
    protected function getMockedHttpClient(): Client
    {
        $accessTokenResponse = json_encode(
            array_filter(
                $this->accessToken,
                function ($key) {
                    return $key !== 'resource_owner_id';
                }
            )
        );

        $handler = new MockHandler(
            [
                new Response(200, ['content-type' => 'application/json'], $accessTokenResponse),
                new Response(500, [], 'Service Unavailable'),
            ]
        );
        $handlerStack = HandlerStack::create($handler);

        return new Client(['handler' => $handlerStack]);
    }

    /**
     * Get a cache mock with
     *
     * @param string|null $currentValue
     *
     * @return CacheInterface|MockObject
     * @throws \ReflectionException
     */
    protected function getMockedCache(string $currentValue = null)
    {
        $this->cacheContainer = [];

        if ($currentValue !== null) {
            $this->cacheContainer[SalesforceAuthorization::CACHE_KEY] = $currentValue;
        }

        /** @var CacheInterface|MockObject $cache */
        $cache = static::getMockForAbstractClass(CacheInterface::class);

        $cache->expects(static::any())
            ->method('has')
            ->with(static::equalTo(SalesforceAuthorization::CACHE_KEY))
            ->willReturnCallback(function () {
                return array_key_exists(SalesforceAuthorization::CACHE_KEY, $this->cacheContainer);
            });

        $cache->expects(static::any())
            ->method('get')
            ->with(static::equalTo(SalesforceAuthorization::CACHE_KEY))
            ->willReturnCallback(function () {
                return $this->cacheContainer[SalesforceAuthorization::CACHE_KEY];
            });

        $cache->expects(static::any())
            ->method('set')
            ->with(
                static::equalTo(SalesforceAuthorization::CACHE_KEY),
                static::callback(
                    function ($accessToken) {
                        $this->cacheContainer[SalesforceAuthorization::CACHE_KEY] = $accessToken;

                        return true;
                    }
                )
            );

        return $cache;
    }
}
