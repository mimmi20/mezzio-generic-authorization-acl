<?php

/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020-2026, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use PHPUnit\Framework\Exception;
use PHPUnit\Framework\TestCase;

use function assert;

final class LaminasAclTest extends TestCase
{
    /**
     * @throws Exception
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function testConstructor(): void
    {
        $acl = self::createStub(Acl::class);

        assert($acl instanceof Acl);
        $laminasAcl = new LaminasAcl($acl);
        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /** @throws Exception */
    public function testIsNotGrantedWithUnknownResource(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $acl = $this->createMock(Acl::class);
        $acl->expects(self::once())
            ->method('hasResource')
            ->with($resource)
            ->willReturn(value: false);
        $acl->expects(self::never())
            ->method('isAllowed');

        assert($acl instanceof Acl);
        $laminasAcl = new LaminasAcl($acl);

        self::assertFalse($laminasAcl->isGranted($role, $resource));
    }

    /** @throws Exception */
    public function testIsGranted(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $acl = $this->createMock(Acl::class);
        $acl->expects(self::once())
            ->method('hasResource')
            ->with($resource)
            ->willReturn(value: true);
        $acl->expects(self::once())
            ->method('isAllowed')
            ->with($role, $resource)
            ->willReturn(value: true);

        assert($acl instanceof Acl);
        $laminasAcl = new LaminasAcl($acl);

        self::assertTrue($laminasAcl->isGranted($role, $resource));
    }

    /** @throws Exception */
    public function testIsGrantedWithoutResourceAndPrivilege(): void
    {
        $role = 'foo';

        $acl = $this->createMock(Acl::class);
        $acl->expects(self::never())
            ->method('isAllowed');

        assert($acl instanceof Acl);
        $laminasAcl = new LaminasAcl($acl);

        self::assertTrue($laminasAcl->isGranted($role));
    }
}
