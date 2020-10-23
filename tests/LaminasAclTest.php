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
use Mezzio\GenericAuthorization\Exception;
use Mezzio\Router\Route;
use Mezzio\Router\RouteResult;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasAclTest extends TestCase
{
    /** @var Acl|ObjectProphecy */
    private $acl;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->acl = $this->prophesize(Acl::class);
    }

    /**
     * @return void
     */
    public function testConstructor(): void
    {
        $laminasAcl = new LaminasAcl($this->acl->reveal());
        self::assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    /**
     * @return void
     */
    public function testIsGrantedWithoutRouteResult(): void
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn(false);

        $laminasAcl = new LaminasAcl($this->acl->reveal());

        $this->expectException(Exception\RuntimeException::class);
        $laminasAcl->isGranted('foo', $request->reveal());
    }

    /**
     * @return void
     */
    public function testIsGranted(): void
    {
        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $this->acl->isAllowed('foo', 'home')->willReturn(true);
        $laminasAcl = new LaminasAcl($this->acl->reveal());

        self::assertTrue($laminasAcl->isGranted('foo', $request->reveal()));
    }

    /**
     * @return void
     */
    public function testIsNotGranted(): void
    {
        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $this->acl->isAllowed('foo', 'home')->willReturn(false);
        $laminasAcl = new LaminasAcl($this->acl->reveal());

        self::assertFalse($laminasAcl->isGranted('foo', $request->reveal()));
    }

    /**
     * @return void
     */
    public function testIsGrantedWithFailedRouting(): void
    {
        $routeResult = $this->getFailureRouteResult(Route::HTTP_METHOD_ANY);

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $laminasAcl = new LaminasAcl($this->acl->reveal());

        $result = $laminasAcl->isGranted('foo', $request->reveal());
        self::assertTrue($result);
    }

    /**
     * @param string $routeName
     *
     * @return \Mezzio\Router\RouteResult
     */
    private function getSuccessRouteResult(string $routeName): RouteResult
    {
        $route = $this->prophesize(Route::class);
        $route->getName()->willReturn($routeName);

        return RouteResult::fromRoute($route->reveal());
    }

    /**
     * @param array|null $methods
     *
     * @return \Mezzio\Router\RouteResult
     */
    private function getFailureRouteResult(?array $methods): RouteResult
    {
        return RouteResult::fromRouteFailure($methods);
    }
}
