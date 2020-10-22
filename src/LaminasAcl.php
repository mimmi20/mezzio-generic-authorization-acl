<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Mezzio\Router\RouteResult;
use Psr\Http\Message\ServerRequestInterface;

class LaminasAcl implements AuthorizationInterface
{
    /**
     * @var Acl
     */
    private $acl;

    /**
     * @param \Laminas\Permissions\Acl\Acl $acl
     */
    public function __construct(Acl $acl)
    {
        $this->acl = $acl;
    }

    /**
     * @param string                                        $role
     * @param string                                        $resource
     * @param \Psr\Http\Message\ServerRequestInterface|null $request
     *
     * @return bool
     */
    public function isGranted(string $role, string $resource, ?ServerRequestInterface $request = null) : bool
    {
        return $this->acl->isAllowed($role, $resource);
    }
}
