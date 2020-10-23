<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);
namespace MezzioTest\GenericAuthorization\Acl;

use Laminas\ServiceManager\ServiceManager;
use Mezzio\GenericAuthorization\Acl\ConfigProvider;
use Mezzio\GenericAuthorization\Acl\LaminasAcl;
use PHPUnit\Framework\TestCase;

final class ConfigProviderTest extends TestCase
{
    /** @var ConfigProvider */
    private $provider;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->provider = new ConfigProvider();
    }

    /**
     * @return array
     */
    public function testInvocationReturnsArray(): array
    {
        $config = ($this->provider)();
        self::assertIsArray($config);

        return $config;
    }

    /**
     * @param array $config
     *
     * @return void
     *
     * @depends testInvocationReturnsArray
     */
    public function testReturnedArrayContainsDependencies(array $config): void
    {
        self::assertArrayHasKey('dependencies', $config);
        self::assertIsArray($config['dependencies']);
        self::assertArrayHasKey('factories', $config['dependencies']);

        $factories = $config['dependencies']['factories'];
        self::assertIsArray($factories);
        self::assertArrayHasKey(LaminasAcl::class, $factories);
    }

    /**
     * @return void
     */
    public function testServicesDefinedInConfigProvider(): void
    {
        $config = ($this->provider)();

        $json = json_decode(
            file_get_contents(__DIR__ . '/../composer.lock'),
            true
        );
        foreach ($json['packages'] as $package) {
            if (!isset($package['extra']['laminas']['config-provider'])) {
                continue;
            }

            $configProvider = new $package['extra']['laminas']['config-provider']();
            $config         = array_merge_recursive($config, $configProvider());
        }

        $config['dependencies']['services']['config'] = [
            'mezzio-authorization-acl' => ['roles' => [], 'resources' => []],
        ];
        $container = $this->getContainer($config['dependencies']);

        $dependencies = $this->provider->getDependencies();
        foreach ($dependencies['factories'] as $name => $factory) {
            self::assertTrue($container->has($name), sprintf('Container does not contain service %s', $name));
            self::assertIsObject(
                $container->get($name),
                sprintf('Cannot get service %s from container using factory %s', $name, $factory)
            );
        }
    }

    /**
     * @param array $dependencies
     *
     * @return \Laminas\ServiceManager\ServiceManager
     */
    private function getContainer(array $dependencies): ServiceManager
    {
        return new ServiceManager($dependencies);
    }
}
