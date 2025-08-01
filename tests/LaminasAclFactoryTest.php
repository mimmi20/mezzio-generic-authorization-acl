<?php

/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020-2025, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Assertion\AssertionInterface;
use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Laminas\Permissions\Acl\Resource\ResourceInterface;
use Laminas\Permissions\Acl\Role\RoleInterface;
use Laminas\ServiceManager\Exception\ServiceNotFoundException;
use Mimmi20\Mezzio\GenericAuthorization\Exception\InvalidConfigException;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;

use function assert;

final class LaminasAclFactoryTest extends TestCase
{
    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
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
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl config provided');

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithConfigException(): void
    {
        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::once())
            ->method('get')
            ->with('config')
            ->willThrowException(new ServiceNotFoundException('test'));
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Could not read mezzio-authorization-acl config');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
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
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl roles configured for LaminasAcl');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
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
                ],
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'No mezzio-authorization-acl resources configured for LaminasAcl',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithEmptyRolesResources(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [],
                'resources' => [],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::never())
            ->method('addRole');
        $acl->expects(self::never())
            ->method('hasResource');
        $acl->expects(self::never())
            ->method('addResource');
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        assert($container instanceof ContainerInterface);
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
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

        $acl     = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher = self::exactly(5);
        $acl->expects($matcher)
            ->method('hasRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admini', $role, (string) $invocation),
                        2 => self::assertSame('administrator', $role, (string) $invocation),
                        3, 4 => self::assertSame('editor', $role, (string) $invocation),
                        default => self::assertSame('contributor', $role, (string) $invocation),
                    };

                    return match ($invocation) {
                        4 => true,
                        default => false,
                    };
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('addRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role, array | RoleInterface | string | null $parents = null) use ($matcher): void {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admini', $role, (string) $invocation),
                        2 => self::assertSame('administrator', $role, (string) $invocation),
                        3 => self::assertSame('editor', $role, (string) $invocation),
                        default => self::assertSame('contributor', $role, (string) $invocation),
                    };

                    match ($invocation) {
                        1 => self::assertSame([], $parents, (string) $invocation),
                        2 => self::assertNull($parents, (string) $invocation),
                        3 => self::assertSame(['administrator'], $parents, (string) $invocation),
                        default => self::assertSame(['editor'], $parents, (string) $invocation),
                    };
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        2 => self::assertSame('admin.posts', $resource, (string) $invocation),
                        3 => self::assertSame('admin.publish', $resource, (string) $invocation),
                        default => self::assertSame('admin.settings', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        2 => self::assertSame('admin.posts', $resource, (string) $invocation),
                        3 => self::assertSame('admin.publish', $resource, (string) $invocation),
                        default => self::assertSame('admin.settings', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        assert($container instanceof ContainerInterface);
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithInvalidRole(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    1 => [],
                ],
                'resources' => [],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with(1)
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with(1, [])
            ->willThrowException(
                new InvalidArgumentException(
                    'addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface',
                ),
            );
        $acl->expects(self::never())
            ->method('hasResource');
        $acl->expects(self::never())
            ->method('addResource');
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithInvalidParentRole(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'editor' => ['administrator'],
                    'administrator' => [1],
                ],
                'resources' => [],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator')
            ->willThrowException(
                new InvalidArgumentException(
                    'addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface',
                ),
            );
        $acl->expects(self::never())
            ->method('hasResource');
        $acl->expects(self::never())
            ->method('addResource');
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithUnknownRole(): void
    {
        $config = [
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
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $acl->expects(self::once())
            ->method('allow')
            ->with('editor', 'admin.dashboard')
            ->willThrowException(new InvalidArgumentException('Role \'editor\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Role \'editor\' not found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithInvalidResource(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [1],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::once())
            ->method('hasResource')
            ->with(1)
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addResource')
            ->with(1)
            ->willThrowException(
                new InvalidArgumentException(
                    'addResource() expects $resource to be of type Laminas\Permissions\Acl\Resource\ResourceInterface',
                ),
            );
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'addResource() expects $resource to be of type Laminas\Permissions\Acl\Resource\ResourceInterface',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithInvalidPermissionsType(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => ['administrator' => 1],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage(
            'the resources must be defined as string or as an array if you want to define privileges',
        );
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithInvalidPermissionsType2(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => [
                    'administrator' => [1],
                ],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $acl->expects(self::once())
            ->method('allow')
            ->with('administrator', 1)
            ->willThrowException(new InvalidArgumentException('Resource \'1\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'1\' not found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithPermissionsAndPrivileges(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => [
                    'administrator' => [
                        'admin.dashboard' => null,
                        'admin.posts' => ['read'],
                    ],
                ],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('allow')
            ->willReturnCallback(
                static function (
                    array | RoleInterface | string | null $roles = null,
                    array | ResourceInterface | string | null $resources = null,
                    array | string | null $privileges = null,
                    AssertionInterface | null $assert = null,
                ) use ($matcher): void {
                    $invocation = $matcher->numberOfInvocations();

                    self::assertSame('administrator', $roles, (string) $invocation);

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resources, (string) $invocation),
                        default => self::assertSame('admin.posts', $resources, (string) $invocation),
                    };

                    match ($invocation) {
                        1 => self::assertNull($privileges, (string) $invocation),
                        default => self::assertSame(['read'], $privileges, (string) $invocation),
                    };

                    self::assertNull($assert, (string) $invocation);
                },
            );
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        assert($container instanceof ContainerInterface);
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithPermissionsException(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => ['administrator' => 'read'],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $acl->expects(self::once())
            ->method('allow')
            ->with('administrator', 'read', null, null)
            ->willThrowException(new InvalidArgumentException('Resource \'read\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'read\' not found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithPermissionsAndPrivileges2(): void
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
                ],
                'allow' => [
                    'editor' => 'admin.posts',
                    'administrator' => [
                        'admin.dashboard' => null,
                        'admin.posts' => ['read'],
                    ],
                ],
            ],
        ];

        $acl     = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher = self::exactly(5);
        $acl->expects($matcher)
            ->method('hasRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admini', $role, (string) $invocation),
                        2 => self::assertSame('administrator', $role, (string) $invocation),
                        3, 4 => self::assertSame('editor', $role, (string) $invocation),
                        default => self::assertSame('contributor', $role, (string) $invocation),
                    };

                    return match ($invocation) {
                        4 => true,
                        default => false,
                    };
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('addRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role, array | RoleInterface | string | null $parents = null) use ($matcher): void {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admini', $role, (string) $invocation),
                        2 => self::assertSame('administrator', $role, (string) $invocation),
                        3 => self::assertSame('editor', $role, (string) $invocation),
                        default => self::assertSame('contributor', $role, (string) $invocation),
                    };

                    match ($invocation) {
                        1 => self::assertSame([], $parents, (string) $invocation),
                        2 => self::assertNull($parents, (string) $invocation),
                        3 => self::assertSame(['administrator'], $parents, (string) $invocation),
                        default => self::assertSame(['editor'], $parents, (string) $invocation),
                    };
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $matcher = self::exactly(3);
        $acl->expects($matcher)
            ->method('allow')
            ->willReturnCallback(
                static function (
                    array | RoleInterface | string | null $roles = null,
                    array | ResourceInterface | string | null $resources = null,
                    array | string | null $privileges = null,
                    AssertionInterface | null $assert = null,
                ) use ($matcher): void {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('editor', $roles, (string) $invocation),
                        default => self::assertSame('administrator', $roles, (string) $invocation),
                    };

                    match ($invocation) {
                        2 => self::assertSame('admin.dashboard', $resources, (string) $invocation),
                        default => self::assertSame('admin.posts', $resources, (string) $invocation),
                    };

                    match ($invocation) {
                        3 => self::assertSame(['read'], $privileges, (string) $invocation),
                        default => self::assertNull($privileges, (string) $invocation),
                    };

                    self::assertNull($assert, (string) $invocation);
                },
            );
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        assert($container instanceof ContainerInterface);
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithPermissionsAndPrivileges3(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'admini' => [],
                    'editor' => ['administrator'],
                    'contributor' => ['editor', 'administrator'],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => [
                    'editor' => ['admin.posts' => null],
                    'administrator' => [
                        'admin.dashboard' => null,
                        'admin.posts' => ['read', 'admin'],
                    ],
                ],
                'deny' => [
                    'administrator' => [
                        'admin.posts' => ['write', 'edit'],
                    ],
                ],
            ],
        ];

        $acl     = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher = self::exactly(6);
        $acl->expects($matcher)
            ->method('hasRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admini', $role, (string) $invocation),
                        2, 5 => self::assertSame('administrator', $role, (string) $invocation),
                        3, 4 => self::assertSame('editor', $role, (string) $invocation),
                        default => self::assertSame('contributor', $role, (string) $invocation),
                    };

                    return match ($invocation) {
                        4, 5 => true,
                        default => false,
                    };
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('addRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role, array | RoleInterface | string | null $parents = null) use ($matcher): void {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admini', $role, (string) $invocation),
                        2 => self::assertSame('administrator', $role, (string) $invocation),
                        3 => self::assertSame('editor', $role, (string) $invocation),
                        default => self::assertSame('contributor', $role, (string) $invocation),
                    };

                    match ($invocation) {
                        1 => self::assertSame([], $parents, (string) $invocation),
                        2 => self::assertNull($parents, (string) $invocation),
                        3 => self::assertSame(['administrator'], $parents, (string) $invocation),
                        default => self::assertSame(
                            ['editor', 'administrator'],
                            $parents,
                            (string) $invocation,
                        ),
                    };
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $matcher = self::exactly(3);
        $acl->expects($matcher)
            ->method('allow')
            ->willReturnCallback(
                static function (
                    array | RoleInterface | string | null $roles = null,
                    array | ResourceInterface | string | null $resources = null,
                    array | string | null $privileges = null,
                    AssertionInterface | null $assert = null,
                ) use ($matcher): void {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('editor', $roles, (string) $invocation),
                        default => self::assertSame('administrator', $roles, (string) $invocation),
                    };

                    match ($invocation) {
                        2 => self::assertSame('admin.dashboard', $resources, (string) $invocation),
                        default => self::assertSame('admin.posts', $resources, (string) $invocation),
                    };

                    match ($invocation) {
                        3 => self::assertSame(['read', 'admin'], $privileges, (string) $invocation),
                        default => self::assertNull($privileges, (string) $invocation),
                    };

                    self::assertNull($assert, (string) $invocation);
                },
            );
        $acl->expects(self::once())
            ->method('deny')
            ->with('administrator', 'admin.posts', ['write', 'edit']);

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        assert($container instanceof ContainerInterface);
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws Exception
     * @throws ContainerExceptionInterface
     * @throws InvalidConfigException
     */
    public function testFactoryWithPermissionsAndPrivilegesException(): void
    {
        $config = [
            'mezzio-authorization-acl' => [
                'roles' => [
                    'administrator' => [],
                ],
                'resources' => [
                    'admin.dashboard',
                    'admin.posts',
                ],
                'allow' => ['administrator' => ['admin.posts' => 'read']],
            ],
        ];

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('hasRole')
            ->with('administrator')
            ->willReturn(false);
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource) use ($matcher): bool {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    return false;
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('admin.dashboard', $resource, (string) $invocation),
                        default => self::assertSame('admin.posts', $resource, (string) $invocation),
                    };

                    self::assertNull($parent, (string) $invocation);

                    return $acl;
                },
            );
        $acl->expects(self::once())
            ->method('allow')
            ->with('administrator', 'admin.posts', 'read', null)
            ->willThrowException(new InvalidArgumentException('Resource \'read\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $matcher   = self::exactly(2);
        $container->expects($matcher)
            ->method('get')
            ->willReturnCallback(
                static function (string $id) use ($matcher, $config, $acl): mixed {
                    $invocation = $matcher->numberOfInvocations();

                    match ($invocation) {
                        1 => self::assertSame('config', $id, (string) $invocation),
                        default => self::assertSame(Acl::class, $id, (string) $invocation),
                    };

                    return match ($invocation) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'read\' not found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }
}
