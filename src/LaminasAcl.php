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
namespace Mezzio\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasAcl implements AuthorizationInterface
{
    /** @var Acl */
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
    public function isGranted(string $role, string $resource, ?ServerRequestInterface $request = null): bool
    {
        return $this->acl->isAllowed($role, $resource);
    }
}
