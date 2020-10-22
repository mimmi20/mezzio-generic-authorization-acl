<?php



declare(strict_types=1);

namespace Mezzio\GenericAuthorization\Acl;

class ConfigProvider
{
    public function __invoke() : array
    {
        return [
            'dependencies' => $this->getDependencies(),
        ];
    }

    public function getDependencies() : array
    {
        return [
            'factories' => [
                LaminasAcl::class => LaminasAclFactory::class,
            ],
        ];
    }
}
