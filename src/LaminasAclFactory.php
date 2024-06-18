<?php
/**
 * This file is part of the mimmi20/mezzio-generic-authorization-acl package.
 *
 * Copyright (c) 2020-2024, Thomas Mueller <mimmi20@live.de>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types = 1);

namespace Mimmi20\Mezzio\GenericAuthorization\Acl;

use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Mimmi20\Mezzio\GenericAuthorization\AuthorizationInterface;
use Mimmi20\Mezzio\GenericAuthorization\Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;

use function assert;
use function is_array;
use function is_numeric;
use function is_string;

final class LaminasAclFactory
{
    /**
     * @throws Exception\InvalidConfigException
     * @throws ContainerExceptionInterface
     */
    public function __invoke(ContainerInterface $container): AuthorizationInterface
    {
        try {
            $config = $container->get('config');

            assert(is_array($config));
        } catch (ContainerExceptionInterface $e) {
            throw new Exception\InvalidConfigException(
                'Could not read mezzio-authorization-acl config',
                0,
                $e,
            );
        }

        $config = $config['mezzio-authorization-acl'] ?? null;

        if ($config === null) {
            throw new Exception\InvalidConfigException('No mezzio-authorization-acl config provided');
        }

        if (!isset($config['roles'])) {
            throw new Exception\InvalidConfigException(
                'No mezzio-authorization-acl roles configured for LaminasAcl',
            );
        }

        if (!isset($config['resources'])) {
            throw new Exception\InvalidConfigException(
                'No mezzio-authorization-acl resources configured for LaminasAcl',
            );
        }

        $acl = $container->get(Acl::class);

        assert($acl instanceof Acl);

        $this->injectRoles($acl, $config['roles']);
        $this->injectResources($acl, $config['resources']);
        $this->injectPermissions($acl, $config['allow'] ?? [], 'allow');
        $this->injectPermissions($acl, $config['deny'] ?? [], 'deny');

        return new LaminasAcl($acl);
    }

    /**
     * @param array<string, array<string>> $roles
     *
     * @throws Exception\InvalidConfigException
     */
    private function injectRoles(Acl $acl, array $roles): void
    {
        foreach ($roles as $role => $parents) {
            foreach ($parents as $parentRole) {
                if ($acl->hasRole($parentRole)) {
                    continue;
                }

                try {
                    $acl->addRole($parentRole);
                } catch (InvalidArgumentException $e) {
                    throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
                }
            }

            try {
                $acl->addRole($role, $parents);
            } catch (InvalidArgumentException $e) {
                throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
            }
        }
    }

    /**
     * @param array<string> $resources
     *
     * @throws Exception\InvalidConfigException
     */
    private function injectResources(Acl $acl, array $resources): void
    {
        foreach ($resources as $resource) {
            try {
                $acl->addResource($resource);
            } catch (InvalidArgumentException $e) {
                throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
            }
        }
    }

    /**
     * @param array<string, array<int|string, string>|string> $permissions
     *
     * @throws Exception\InvalidConfigException
     */
    private function injectPermissions(Acl $acl, array $permissions, string $type): void
    {
        foreach ($permissions as $role => $resources) {
            if (is_string($resources)) {
                try {
                    $acl->{$type}($role, $resources);
                } catch (InvalidArgumentException $e) {
                    throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
                }

                continue;
            }

            if (is_array($resources)) {
                foreach ($resources as $resource => $privileges) {
                    if (is_numeric($resource)) {
                        try {
                            $acl->{$type}($role, $privileges);
                        } catch (InvalidArgumentException $e) {
                            throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
                        }

                        continue;
                    }

                    try {
                        $acl->{$type}($role, $resource, $privileges);
                    } catch (InvalidArgumentException $e) {
                        throw new Exception\InvalidConfigException($e->getMessage(), 0, $e);
                    }
                }

                continue;
            }

            throw new Exception\InvalidConfigException(
                'the resources must be defined as string or as an array if you want to define privileges',
            );
        }
    }
}
