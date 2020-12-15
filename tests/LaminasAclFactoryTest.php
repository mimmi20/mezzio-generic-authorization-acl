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

use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Laminas\ServiceManager\Exception\ServiceNotFoundException;
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
        $container->expects(self::never())
            ->method('has');

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

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Could not read mezzio-authorization-acl config');
        $this->expectExceptionCode(0);

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
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl roles configured for LaminasAcl');
        $this->expectExceptionCode(0);

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
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('No mezzio-authorization-acl resources configured for LaminasAcl');
        $this->expectExceptionCode(0);

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
            ->method('addResource');
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

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

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::exactly(2))
            ->method('hasRole')
            ->withConsecutive(['administrator'], ['editor'])
            ->willReturnOnConsecutiveCalls(false, true);
        $acl->expects(self::exactly(4))
            ->method('addRole')
            ->withConsecutive(['admini'], ['administrator'], ['editor', ['administrator']], ['contributor', ['editor']]);
        $acl->expects(self::exactly(4))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts'], ['admin.publish'], ['admin.settings']);
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with(1, [])
            ->willThrowException(new InvalidArgumentException('addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface'));
        $acl->expects(self::never())
            ->method('addResource');
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('addRole() expects $role to be of type Laminas\\Permissions\\Acl\\Role\\RoleInterface');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
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
            ->willThrowException(new InvalidArgumentException('addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface'));
        $acl->expects(self::never())
            ->method('addResource');
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('addRole() expects $role to be of type Laminas\Permissions\Acl\Role\RoleInterface');
        $this->expectExceptionCode(0);

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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::once())
            ->method('allow')
            ->with('editor', 'admin.dashboard')
            ->willThrowException(new InvalidArgumentException('Role \'editor\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Role \'editor\' not found');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::once())
            ->method('addResource')
            ->with(1)
            ->willThrowException(new InvalidArgumentException('addResource() expects $resource to be of type Laminas\Permissions\Acl\Resource\ResourceInterface'));
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('addResource() expects $resource to be of type Laminas\Permissions\Acl\Resource\ResourceInterface');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::never())
            ->method('allow');
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('the resources must be defined as string or as an array if you want to define privileges');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     *
     * @return void
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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::once())
            ->method('allow')
            ->with('administrator', 1)
            ->willThrowException(new InvalidArgumentException('Resource \'1\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'1\' not found');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::exactly(2))
            ->method('allow')
            ->withConsecutive(['administrator', 'admin.dashboard', null], ['administrator', 'admin.posts', ['read']]);
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

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
        $acl->expects(self::never())
            ->method('hasRole');
        $acl->expects(self::once())
            ->method('addRole')
            ->with('administrator');
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::once())
            ->method('allow')
            ->with('administrator', 'read', null, null)
            ->willThrowException(new InvalidArgumentException('Resource \'read\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'read\' not found');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::exactly(2))
            ->method('hasRole')
            ->withConsecutive(['administrator'], ['editor'])
            ->willReturnOnConsecutiveCalls(false, true);
        $acl->expects(self::exactly(4))
            ->method('addRole')
            ->withConsecutive(['admini'], ['administrator'], ['editor', ['administrator']], ['contributor', ['editor']]);
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::exactly(3))
            ->method('allow')
            ->withConsecutive(['editor', 'admin.posts', null], ['administrator', 'admin.dashboard', null], ['administrator', 'admin.posts', ['read']]);
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        /** @var ContainerInterface $container */
        $laminasAcl = $factory($container);

        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
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

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::exactly(3))
            ->method('hasRole')
            ->withConsecutive(['administrator'], ['editor'], ['administrator'])
            ->willReturnOnConsecutiveCalls(false, true, true);
        $acl->expects(self::exactly(4))
            ->method('addRole')
            ->withConsecutive(['admini'], ['administrator'], ['editor', ['administrator']], ['contributor', ['editor', 'administrator']]);
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::exactly(3))
            ->method('allow')
            ->withConsecutive(['editor', 'admin.posts', null], ['administrator', 'admin.dashboard', null], ['administrator', 'admin.posts', ['read', 'admin']]);
        $acl->expects(self::once())
            ->method('deny')
            ->with('administrator', 'admin.posts', ['write', 'edit']);

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

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
        $acl->expects(self::exactly(2))
            ->method('addResource')
            ->withConsecutive(['admin.dashboard'], ['admin.posts']);
        $acl->expects(self::once())
            ->method('allow')
            ->with('administrator', 'admin.posts', 'read', null)
            ->willThrowException(new InvalidArgumentException('Resource \'read\' not found'));
        $acl->expects(self::never())
            ->method('deny');

        $container = $this->getMockBuilder(ContainerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $container->expects(self::exactly(2))
            ->method('get')
            ->withConsecutive(['config'], [Acl::class])
            ->willReturnOnConsecutiveCalls($config, $acl);
        $container->expects(self::never())
            ->method('has');

        $factory = new LaminasAclFactory();

        $this->expectException(Exception\InvalidConfigException::class);
        $this->expectExceptionMessage('Resource \'read\' not found');
        $this->expectExceptionCode(0);

        /* @var ContainerInterface $container */
        $factory($container);
    }
}
