<?php

namespace DMT\Test\Salesforce\Auth\Fixtures;

use Psr\SimpleCache\InvalidArgumentException;

/**
 * Class CacheException
 *
 * @package DMT\Salesforce\Auth
 */
class CacheException extends \LogicException implements InvalidArgumentException
{

}
