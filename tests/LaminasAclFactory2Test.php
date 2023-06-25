<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020-2023, Thomas Mueller <mimmi20@live.de>
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
use Mimmi20\Mezzio\GenericAuthorization\Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

use function assert;

final class LaminasAclFactory2Test extends TestCase
{
    /** @throws \PHPUnit\Framework\Exception */
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
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('hasRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('administrator', $role),
                        default => self::assertSame('editor', $role),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => false,
                        default => true,
                    };
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('addRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role, array | RoleInterface | string | null $parents = null) use ($matcher): void {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('admini', $role),
                        2 => self::assertSame('administrator', $role),
                        3 => self::assertSame('editor', $role),
                        default => self::assertSame('contributor', $role),
                    };

                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame([], $parents),
                        2 => self::assertNull($parents),
                        3 => self::assertSame(['administrator'], $parents),
                        default => self::assertSame(['editor'], $parents),
                    };
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('admin.dashboard', $resource),
                        default => self::assertSame('admin.posts', $resource),
                    };

                    self::assertNull($parent);

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
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('editor', $roles),
                        default => self::assertSame('administrator', $roles),
                    };

                    match ($matcher->numberOfInvocations()) {
                        2 => self::assertSame('admin.dashboard', $resources),
                        default => self::assertSame('admin.posts', $resources),
                    };

                    match ($matcher->numberOfInvocations()) {
                        3 => self::assertSame(['read'], $privileges),
                        default => self::assertNull($privileges),
                    };

                    self::assertNull($assert);
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
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('config', $id),
                        default => self::assertSame(Acl::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
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

    /** @throws \PHPUnit\Framework\Exception */
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
        $matcher = self::exactly(3);
        $acl->expects($matcher)
            ->method('hasRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role) use ($matcher): bool {
                    match ($matcher->numberOfInvocations()) {
                        2 => self::assertSame('editor', $role),
                        default => self::assertSame('administrator', $role),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => false,
                        default => true,
                    };
                },
            );
        $matcher = self::exactly(4);
        $acl->expects($matcher)
            ->method('addRole')
            ->willReturnCallback(
                static function (RoleInterface | string $role, array | RoleInterface | string | null $parents = null) use ($matcher): void {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('admini', $role),
                        2 => self::assertSame('administrator', $role),
                        3 => self::assertSame('editor', $role),
                        default => self::assertSame('contributor', $role),
                    };

                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame([], $parents),
                        2 => self::assertNull($parents),
                        3 => self::assertSame(['administrator'], $parents),
                        default => self::assertSame(['editor', 'administrator'], $parents),
                    };
                },
            );
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('admin.dashboard', $resource),
                        default => self::assertSame('admin.posts', $resource),
                    };

                    self::assertNull($parent);

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
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('editor', $roles),
                        default => self::assertSame('administrator', $roles),
                    };

                    match ($matcher->numberOfInvocations()) {
                        2 => self::assertSame('admin.dashboard', $resources),
                        default => self::assertSame('admin.posts', $resources),
                    };

                    match ($matcher->numberOfInvocations()) {
                        3 => self::assertSame(['read', 'admin'], $privileges),
                        default => self::assertNull($privileges),
                    };

                    self::assertNull($assert);
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
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('config', $id),
                        default => self::assertSame(Acl::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
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

    /** @throws \PHPUnit\Framework\Exception */
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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $matcher = self::exactly(2);
        $acl->expects($matcher)
            ->method('addResource')
            ->willReturnCallback(
                static function (ResourceInterface | string $resource, ResourceInterface | string | null $parent = null) use ($matcher, $acl): Acl {
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('admin.dashboard', $resource),
                        default => self::assertSame('admin.posts', $resource),
                    };

                    self::assertNull($parent);

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
                    match ($matcher->numberOfInvocations()) {
                        1 => self::assertSame('config', $id),
                        default => self::assertSame(Acl::class, $id),
                    };

                    return match ($matcher->numberOfInvocations()) {
                        1 => $config,
                        default => $acl,
                    };
                },
            );
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'read\' not found');
        $this->expectExceptionCode(0);

        assert($container instanceof ContainerInterface);
        $factory($container);
    }
}
