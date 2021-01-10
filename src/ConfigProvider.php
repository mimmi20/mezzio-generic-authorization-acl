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
use Laminas\ServiceManager\Factory\InvokableFactory;
use Mezzio\GenericAuthorization\AuthorizationInterface;

final class ConfigProvider
{
    /**
     * @return array[]
     */
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencies(),
        ];
    }

    /**
     * @return array
     */
    public function getDependencies(): array
    {
        return [
            'aliases' => [
                AuthorizationInterface::class => LaminasAcl::class,
            ],
            'factories' => [
                Acl::class => InvokableFactory::class,
                LaminasAcl::class => LaminasAclFactory::class,
            ],
        ];
    }
}
