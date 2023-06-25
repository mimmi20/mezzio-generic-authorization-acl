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
use Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface;
use Psr\Http\Message\ServerRequestInterface;

final class LaminasAcl implements AuthorizationInterface
{
    /** @throws void */
    public function __construct(private readonly Acl $acl)
    {
        // nothing to do
    }

    /**
     * Check if a role is granted for a resource
     *
     * @throws void
     *
     * @phpcsSuppress SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
     */
    public function isGranted(
        string | null $role = null,
        string | null $resource = null,
        string | null $privilege = null,
        ServerRequestInterface | null $request = null,
    ): bool {
        if ($resource === null && $privilege === null) {
            return true;
        }

        if ($resource !== null && !$this->acl->hasResource($resource)) {
            return false;
        }

        return $this->acl->isAllowed($role, $resource, $privilege);
    }
}
