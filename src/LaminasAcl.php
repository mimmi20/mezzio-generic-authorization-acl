<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020-2021, Thomas Mueller <mimmi20@live.de>
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
    private Acl $acl;

    public function __construct(Acl $acl)
    {
        $this->acl = $acl;
    }

    /**
     * Check if a role is granted for a resource
     *
     * @phpcsSuppress SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
     */
    public function isGranted(?string $role = null, ?string $resource = null, ?string $privilege = null, ?ServerRequestInterface $request = null): bool
    {
        if (null === $resource && null === $privilege) {
            return true;
        }

        if (null !== $resource && !$this->acl->hasResource($resource)) {
            return false;
        }

        return $this->acl->isAllowed($role, $resource, $privilege);
    }
}
