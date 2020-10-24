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
use Psr\Container\ContainerInterface;

final class LaminasAclFactoryTest extends TestCase
{
    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryWithoutConfig(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn([]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl config provided');

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryWithoutLaminasAclConfig(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(['mezzio-authorization-acl' => []]);

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl roles configured for LaminasAcl');

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryWithoutResources(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-acl' => [
                        'roles' => [],
                    ],
                ]
            );

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl resources configured for LaminasAcl');

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testFactoryWithEmptyRolesResources(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-acl' => [
                        'roles' => [],
                        'resources' => [],
                    ],
                ]
            );

        $factory = new LaminasAclFactory();

        /** @var ContainerInterface $container */
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
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
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn($config);

        $factory = new LaminasAclFactory();

        /** @var ContainerInterface $container */
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryWithInvalidRole(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
                    'mezzio-authorization-acl' => [
                        'roles' => [
                            1 => [],
                        ],
                        'permissions' => [],
                        'resources' => [],
                    ],
                ]
            );

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('addRole() expects $role to be of type Laminas\\Permissions\\Acl\\Role\\RoleInterface');

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
     */
    public function testFactoryWithUnknownRole(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willReturn(
                [
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
                ]
            );

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Role \'editor\' not found');

        /* @var ContainerInterface $container */
        $factory($container);
    }
}
