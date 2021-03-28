<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020-2021, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace MezzioTest\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use Mezzio\GenericAuthorization\Acl\ConfigProvider;
use Mezzio\GenericAuthorization\Acl\LaminasAcl;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use SebastianBergmann\RecursionContext\InvalidArgumentException;

final class ConfigProviderTest extends TestCase
{
    private ConfigProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new ConfigProvider();
    }

    /**
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function testReturnedArrayContainsDependencies(): void
    {
        $config = ($this->provider)();
        self::assertIsArray($config);

        self::assertArrayHasKey('dependencies', $config);

        $dependencies = $config['dependencies'];
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);
        self::assertArrayHasKey('aliases', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(LaminasAcl::class, $factories);
        self::assertArrayHasKey(Acl::class, $factories);

        $aliases = $dependencies['aliases'];
        self::assertIsArray($aliases);
        self::assertArrayHasKey(AuthorizationInterface::class, $aliases);
    }

    /**
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function testGetDependenciesReturnedArrayContainsDependencies(): void
    {
        $dependencies = $this->provider->getDependencies();
        self::assertIsArray($dependencies);
        self::assertArrayHasKey('factories', $dependencies);
        self::assertArrayHasKey('aliases', $dependencies);

        $factories = $dependencies['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(LaminasAcl::class, $factories);
        self::assertArrayHasKey(Acl::class, $factories);

        $aliases = $dependencies['aliases'];
        self::assertIsArray($aliases);
        self::assertArrayHasKey(AuthorizationInterface::class, $aliases);
    }
}
