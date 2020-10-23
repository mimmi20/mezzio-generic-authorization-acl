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

use Mezzio\GenericAuthorization\Acl\LaminasAcl;
use Mezzio\GenericAuthorization\Acl\LaminasAclFactory;
use Mezzio\GenericAuthorization\Exception;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Container\ContainerInterface;

final class LaminasAclFactoryTest extends TestCase
{
    /** @var ContainerInterface|ObjectProphecy */
    private $container;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->container = $this->prophesize(ContainerInterface::class);
    }

    /**
     * @return void
     */
    public function testFactoryWithoutConfig(): void
    {
        $this->container->get('config')->willReturn([]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithoutLaminasAclConfig(): void
    {
        $this->container->get('config')->willReturn(['mezzio-authorization-acl' => []]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithoutResources(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-acl' => [
                'roles' => [],
            ],
        ]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithEmptyRolesResources(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-acl' => [
                'roles' => [],
                'resources' => [],
            ],
        ]);

        $factory    = new LaminasAclFactory();
        $laminasAcl = $factory($this->container->reveal());
        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @return void
     */
    public function testFactoryWithoutAllowOrDeny(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'admini' => [],
                    'editor' => ['administrator'],
                    'contributor' => ['editor'],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                    'admin.publish',
                    'admin.settings',
                ],
            ],
        ];
        $this->container->get('config')->willReturn($config);

        $factory    = new LaminasAclFactory();
        $laminasAcl = $factory($this->container->reveal());
        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @return void
     */
    public function testFactoryWithInvalidRole(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-acl' => [
                'roles' => [
                    1 => [],
                ],
                'permissions' => [],
            ],
        ]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }

    /**
     * @return void
     */
    public function testFactoryWithUnknownRole(): void
    {
        $this->container->get('config')->willReturn([
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => [
                    'editor' => ['admin.dashboard'],
                ],
            ],
        ]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $factory($this->container->reveal());
    }
}
