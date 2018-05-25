<?php

namespace DMT\Salesforce\Auth\Authorization;

use DMT\Auth\AuthorizationException;
use DMT\Auth\AuthorizationInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\RequestInterface;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use Stevenmaguire\OAuth2\Client\Provider\Salesforce;
use Stevenmaguire\OAuth2\Client\Token\AccessToken;

/**
 * Class SalesforceAuthorization
 *
 * @package DMT\Salesforce\Auth
 */
class SalesforceAuthorization implements AuthorizationInterface
{
    /**
     * @static string The key where the access token is stored for later use.
     */
    const CACHE_KEY = 'salesforce_access_token';

    /**
     * @static int Salesforce does not say when token expires, it is set to 1 hour for now.
     */
    const CACHE_TTL = 3600;

    /**
     * @var Salesforce
     */
    protected $provider;

    /**
     * @var array
     */
    protected $credentials;

    /**
     * @var CacheInterface|null
     */
    protected $cache;

    /**
     * SalesforceAuthorization constructor.
     *
     * @param Salesforce $provider
     * @param string $username The username of the user to logon.
     * @param string $password The password appended by the securityToken for the user.
     * @param CacheInterface|null $cache
     */
    public function __construct(Salesforce $provider, string $username, string $password, CacheInterface $cache = null)
    {
        $this->provider = $provider;
        $this->credentials = compact('username', 'password');
        $this->cache = $cache;
    }

    /**
     * Get a request with the headers associated with the authorization.
     *
     * @param RequestInterface $request
     *
     * @return RequestInterface
     * @throws AuthorizationException
     * @throws InvalidArgumentException
     */
    public function handle(RequestInterface $request): RequestInterface
    {
        try {
            $accessToken = $this->fetchAccessTokenFromCache() ?? $this->fetchAccessToken();

            $endPoint = parse_url($accessToken->getInstanceUrl(), PHP_URL_HOST);

            if ($endPoint !== $request->getUri()->getHost()) {
                $request = $request->withUri($request->getUri()->withHost($endPoint));
            }

            return $request->withHeader('Authorization', sprintf('Bearer %s', $accessToken));
        } catch (InvalidArgumentException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new AuthorizationException("Authentication failed: " . $exception->getMessage(), 0, $exception);
        }
    }

    /**
     * Get AccessToken using the grant_type password flow.
     *
     * @return AccessToken
     * @throws IdentityProviderException
     * @throws InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    protected function fetchAccessToken(): AccessToken
    {
        /** @var AccessToken $accessToken */
        $accessToken = $this->provider->getAccessToken('password', $this->credentials);

        if ($this->cache !== null) {
            $this->cache->set(static::CACHE_KEY, json_encode($accessToken), static::CACHE_TTL);
        }

        return $accessToken;
    }

    /**
     * Get a access token from cache.
     *
     * @return null|AccessToken
     * @throws InvalidArgumentException
     */
    protected function fetchAccessTokenFromCache(): ?AccessToken
    {
        try {
            if ($this->cache !== null && $this->cache->has(static::CACHE_KEY)) {
                return new AccessToken(json_decode($this->cache->get(static::CACHE_KEY), true));
            }
        } catch (\InvalidArgumentException $exception) {
            // The cache will be corrected when the AccessToken is retrieved
        }

        return null;
    }
}
