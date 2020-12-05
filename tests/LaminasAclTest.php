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
use Mezzio\GenericAuthorization\Acl\LaminasAcl;
use PHPUnit\Framework\TestCase;

final class LaminasAclTest extends TestCase
{
    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testConstructor(): void
    {
        $acl = $this->createMock(Acl::class);

        /** @var Acl $acl */
        $laminasAcl = new LaminasAcl($acl);
        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testIsNotGranted(): void
    {
        $role     = 'foo';
        $resource = 'bar';

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::once())
            ->method('isAllowed')
            ->with($role, $resource)
            ->willReturn(false);

        /** @var Acl $acl */
        $laminasAcl = new LaminasAcl($acl);

        self::assertFalse($laminasAcl->isGranted($role, $resource));
    }

    /**
     * @throws \Mezzio\GenericAuthorization\Exception\RuntimeException
     * @throws \PHPUnit\Framework\ExpectationFailedException
     * @throws \PHPUnit\Framework\MockObject\RuntimeException
     * @throws \SebastianBergmann\RecursionContext\InvalidArgumentException
     *
     * @return void
     */
    public function testIsGrantedWithoutResourceAndPrivilege(): void
    {
        $role     = 'foo';

        $acl = $this->getMockBuilder(Acl::class)
            ->disableOriginalConstructor()
            ->getMock();
        $acl->expects(self::never())
            ->method('isAllowed');

        /** @var Acl $acl */
        $laminasAcl = new LaminasAcl($acl);

        self::assertTrue($laminasAcl->isGranted($role));
    }
}
