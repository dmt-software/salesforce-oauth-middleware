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
     * @var string
     */
    protected $accessToken;

    /**
     * Store a json token response body.
     */
    public function setUp()
    {
        $this->accessToken = json_encode([
            'instance_url' => 'https://user-3001.cloudforce.com',
            'id' => 'https://login.salesforce.com/id/00Db0000000bF1jN44/005b0000005jPFjAAM',
            'token_type' => 'Bearer',
            'issued_at' => strval(time()),
            'signature' => 'ODExMDQ5ODk5ODA=',
            'access_token' => '00Db0000000bHq1!Mu5eb70Rk_3Tc...',
        ]);
    }

    /**
     * Test the happy flow.
     */
    public function testAuthorization()
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $accessToken = new AccessToken(json_decode($this->accessToken, true));
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
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \ReflectionException
     */
    public function testAuthorizationWithCache()
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $accessToken = new AccessToken(json_decode($this->accessToken, true));
        $request = new Request('GET', 'https://salesforce.com/services/data/v42.0/');
        $cache = $this->getMockedCache();

        $authorization = new SalesforceAuthorization($provider, 'user@org.salesforce.com', 'pass1234', $cache);
        $authRequest = $authorization->handle($request);

        static::assertEmpty($request->getHeaderLine('Authorization'));
        static::assertNotEquals($request->getUri()->getHost(), $authRequest->getUri()->getHost());
        static::assertContains($authRequest->getUri()->getHost(), $accessToken->getInstanceUrl());
        static::assertContains($accessToken->getToken(), $authRequest->getHeaderLine('Authorization'));
        static::assertContains($accessToken->getToken(), $cache->get(SalesforceAuthorization::CACHE_KEY));

        $cache->expects(static::once())->method('get');
        $cache->expects(static::never())->method('set');

        $authRequest = $authorization->handle($request);

        static::assertContains($authRequest->getUri()->getHost(), $accessToken->getInstanceUrl());
        static::assertContains($accessToken->getToken(), $authRequest->getHeaderLine('Authorization'));
    }

    /**
     * Test access token is retrieved from cache.
     *
     * @throws \ReflectionException
     */
    public function testAuthorizationFromCache()
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $cache = $this->getMockedCache(
            json_encode([
                'instance_url' => 'https://user-3002.cloudforce.com',
                'id' => 'https://login.salesforce.com/id/00Db0000000bF1nB9c/004b0000004pJn5AAZ',
                'token_type' => 'Bearer',
                'issued_at' => strval(time()),
                'signature' => 'bjRHXHRzZjA=',
                'access_token' => '00Db0000000bHa7!r4D10.h43d...',
            ])
        );

        $cache->expects(static::once())->method('get');
        $cache->expects(static::never())->method('set');

        $authorization = new SalesforceAuthorization($provider, 'user@org.salesforce.com', 'pass1234', $cache);
        $authRequest = $authorization->handle(new Request('GET', 'https://salesforce.com/services/data/v42.0/'));

        static::assertSame('user-3002.cloudforce.com', $authRequest->getUri()->getHost());
        static::assertContains('00Db0000000bHa7!r4D10.h43d...', $authRequest->getHeaderLine('Authorization'));
    }


    /**
     * @dataProvider provideAuthorizationExceptions
     *
     * @expectedException \DMT\Auth\AuthorizationException
     * @expectedExceptionMessageRegExp ~Authentication failed: ~
     *
     * @param GuzzleException $exception
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
     * @throws \ReflectionException
     */
    public function testDisableIncompatibleCache()
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());

        /** @var CacheInterface|MockObject $cache */
        $cache = static::getMockForAbstractClass(CacheInterface::class);
        $cache->expects(static::once())
            ->method('has')
            ->willThrowException(new CacheException('Illegal cache key'));
        $cache->expects(static::never())
            ->method('set');

        $authorization = new SalesforceAuthorization($provider, 'user@organisation.salesforce.com', 'pass1234', $cache);
        $authorization->handle(new Request('GET', 'https://localhost'));

        static::assertAttributeNotInstanceOf(CacheInterface::class, 'cache', $authorization);
    }

    /**
     * Bit of an edge case; I would expect the cache::has to fail before the cache::set is called.
     *
     * @throws \ReflectionException
     */
    public function testDisableIncompatibleCacheOnStore()
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());

        /** @var CacheInterface|MockObject $cache */
        $cache = static::getMockForAbstractClass(CacheInterface::class);
        $cache->expects(static::once())
            ->method('has')
            ->willReturn(false);
        $cache->expects(static::once())
            ->method('set')
            ->willThrowException(new CacheException('Illegal cache key'));

        $authorization = new SalesforceAuthorization($provider, 'user@organisation.salesforce.com', 'pass1234', $cache);
        $authorization->handle(new Request('GET', 'https://localhost'));

        static::assertAttributeNotInstanceOf(CacheInterface::class, 'cache', $authorization);
    }

    /**
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \ReflectionException
     */
    public function testIgnoreAndOverwriteInvalidCacheToken()
    {
        $provider = $this->getMockedSalesforceProvider($this->getMockedHttpClient());
        $cache = $this->getMockedCache('{}');

        static::assertArrayNotHasKey(
            'access_token',
            json_decode($cache->get(SalesforceAuthorization::CACHE_KEY), true)
        );

        $authorization = new SalesforceAuthorization($provider, 'user', 'pass', $cache);
        $authorization->handle(new Request('GET', 'https://localhost'));

        static::assertArrayHasKey(
            'access_token',
            json_decode($cache->get(SalesforceAuthorization::CACHE_KEY), true)
        );
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
        return
            new Client(
                [
                    'handler' => HandlerStack::create(
                        new MockHandler(
                            [new Response(200, ['content-type' => 'application/json'], $this->accessToken)]
                        )
                    )
                ]
            );
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
        $cacheData = [];

        if ($currentValue !== null) {
            $cacheData[SalesforceAuthorization::CACHE_KEY] = $currentValue;
        }

        /** @var CacheInterface|MockObject $cache */
        $cache = static::getMockForAbstractClass(CacheInterface::class);
        $cache->expects(static::any())
            ->method('has')
            ->with(static::equalTo(SalesforceAuthorization::CACHE_KEY))
            ->willReturnCallback(function () use (&$cacheData) {
                return array_key_exists(SalesforceAuthorization::CACHE_KEY, $cacheData);
            });

        $cache->expects(static::any())
            ->method('get')
            ->with(static::equalTo(SalesforceAuthorization::CACHE_KEY))
            ->willReturnCallback(function () use (&$cacheData) {
                return $cacheData[SalesforceAuthorization::CACHE_KEY];
            });

        $cache->expects(static::any())
            ->method('set')
            ->with(
                static::equalTo(SalesforceAuthorization::CACHE_KEY),
                static::callback(
                    function ($accessToken) use (&$cacheData) {
                        $cacheData[SalesforceAuthorization::CACHE_KEY] = $accessToken;

                        return true;
                    }
                )
            );

        return $cache;
    }
}
