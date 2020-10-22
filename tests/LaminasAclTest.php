<?php



declare(strict_types=1);

namespace MezzioTest\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use Mezzio\GenericAuthorization\Acl\LaminasAcl;
use Mezzio\GenericAuthorization\Exception;
use Mezzio\Router\Route;
use Mezzio\Router\RouteResult;
use PHPUnit\Framework\TestCase;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ServerRequestInterface;

class LaminasAclTest extends TestCase
{
    /** @var Acl|ObjectProphecy */
    private $acl;

    protected function setUp() : void
    {
        $this->acl = $this->prophesize(Acl::class);
    }

    public function testConstructor()
    {
        $laminasAcl = new LaminasAcl($this->acl->reveal());
        $this->assertInstanceOf(LaminasAcl::class, $laminasAcl);
    }

    public function testIsGrantedWithoutRouteResult()
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn(false);

        $laminasAcl = new LaminasAcl($this->acl->reveal());

        $this->expectException(Exception\RuntimeException::class);
        $laminasAcl->isGranted('foo', $request->reveal());
    }

    public function testIsGranted()
    {
        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $this->acl->isAllowed('foo', 'home')->willReturn(true);
        $laminasAcl = new LaminasAcl($this->acl->reveal());

        $this->assertTrue($laminasAcl->isGranted('foo', $request->reveal()));
    }

    public function testIsNotGranted()
    {
        $routeResult = $this->getSuccessRouteResult('home');

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $this->acl->isAllowed('foo', 'home')->willReturn(false);
        $laminasAcl = new LaminasAcl($this->acl->reveal());

        $this->assertFalse($laminasAcl->isGranted('foo', $request->reveal()));
    }

    public function testIsGrantedWithFailedRouting()
    {
        $routeResult = $this->getFailureRouteResult(Route::HTTP_METHOD_ANY);

        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(RouteResult::class, false)->willReturn($routeResult);

        $laminasAcl = new LaminasAcl($this->acl->reveal());

        $result = $laminasAcl->isGranted('foo', $request->reveal());
        $this->assertTrue($result);
    }

    private function getSuccessRouteResult(string $routeName): RouteResult
    {
        $route = $this->prophesize(Route::class);
        $route->getName()->willReturn($routeName);

        return RouteResult::fromRoute($route->reveal());
    }

    private function getFailureRouteResult(?array $methods): RouteResult
    {
        return RouteResult::fromRouteFailure($methods);
    }
}
