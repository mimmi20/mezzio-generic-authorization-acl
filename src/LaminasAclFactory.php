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
use Laminas\Permissions\Acl\Exception\InvalidArgumentException;
use Mezzio\GenericAuthorization\AuthorizationInterface;
use Mezzio\GenericAuthorization\Exception;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;

final class LaminasAclFactory
{
    /**
     * @param \Psr\Container\ContainerInterface $container
     *
     * @throws Exception\InvalidConfigException
     * @throws \Psr\Container\ContainerExceptionInterface
     *
     * @return \Mezzio\GenericAuthorization\AuthorizationInterface
     */
    public function __invoke(ContainerInterface $container): AuthorizationInterface
    {
        try {
            $config = $container->get('config')['mezzio-authorization-acl'] ?? null;
        } catch (ContainerExceptionInterface $e) {
            throw new Exception\InvalidConfigException(
                'Could not read mezzio-authorization-acl config',
                0,
                $e
            );
        }

        if (null === $config) {
            throw new Exception\InvalidConfigException(
                'No mezzio-authorization-acl config provided'
            );
        }

        if (!isset($config['roles'])) {
            throw new Exception\InvalidConfigException(
                'No mezzio-authorization-acl roles configured for LaminasAcl'
            );
        }

        if (!isset($config['resources'])) {
            throw new Exception\InvalidConfigException(
                'No mezzio-authorization-acl resources configured for LaminasAcl'
            );
        }

        $acl = $container->get(Acl::class);

        $this->injectRoles($acl, $config['roles']);
        $this->injectResources($acl, $config['resources']);
        $this->injectPermissions($acl, $config['allow'] ?? [], 'allow');
        $this->injectPermissions($acl, $config['deny'] ?? [], 'deny');

        return new LaminasAcl($acl);
    }

    /**
     * @param Acl   $acl
     * @param array $roles
     *
     * @throws Exception\InvalidConfigException
     *
     * @return void
     */
    private function injectRoles(Acl $acl, array $roles): void
    {
        foreach ($roles as $role => $parents) {
            foreach ($parents as $parent) {
                if ($acl->hasRole($parent)) {
                    continue;
                }

                try {
                    $acl->addRole($parent);
                } catch (InvalidArgumentException $e) {
                    throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
                }
            }

            try {
                $acl->addRole($role, $parents);
            } catch (InvalidArgumentException $e) {
                throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @param Acl   $acl
     * @param array $resources
     *
     * @throws Exception\InvalidConfigException
     *
     * @return void
     */
    private function injectResources(Acl $acl, array $resources): void
    {
        foreach ($resources as $resource) {
            try {
                $acl->addResource($resource);
            } catch (InvalidArgumentException $e) {
                throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @param Acl    $acl
     * @param array  $permissions
     * @param string $type
     *
     * @throws Exception\InvalidConfigException
     *
     * @return void
     */
    private function injectPermissions(Acl $acl, array $permissions, string $type): void
    {
        foreach ($permissions as $role => $resources) {
            if (is_string($resources)) {
                try {
                    $acl->{$type}($role, $resources);
                } catch (InvalidArgumentException $e) {
                    throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
                }

                continue;
            }

            if (is_array($resources)) {
                foreach ($resources as $resource => $privileges) {
                    if (is_numeric($resource)) {
                        try {
                            $acl->{$type}($role, $privileges);
                        } catch (InvalidArgumentException $e) {
                            throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
                        }
                    } else {
                        try {
                            $acl->{$type}($role, $resource, $privileges);
                        } catch (InvalidArgumentException $e) {
                            throw new Exception\InvalidConfigException($e->getMessage(), $e->getCode(), $e);
                        }
                    }
                }

                continue;
            }

            throw new Exception\InvalidConfigException(
                'the resources must be defined as string or as an array if you want to define privileges'
            );
        }
    }
}
