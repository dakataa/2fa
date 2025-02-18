<?php

namespace Dakataa\Security\TwoFactorAuthenticator;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class DakataaTwoFactorAuthenticatorBundle extends AbstractBundle
{

	public function configure(DefinitionConfigurator $definition): void
	{
        $definition
            ->rootNode()
            ->children()
                ->booleanNode('enabled')
                    ->defaultValue(false)
                ->end()
                ->scalarNode('code_parameter')
                    ->defaultValue('code')
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('username_parameter')
                    ->defaultValue('username')
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('form_path')
                    ->defaultValue('/2fa/form')
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('check_path')
                    ->defaultValue('/2fa/check')
                    ->cannotBeEmpty()
                ->end()
            ->end()
        ;
	}

	public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
	{
        $configDir = new FileLocator(__DIR__.'/../config');
        $loader = new YamlFileLoader($builder, $configDir);
        $loader->load('services.yaml');

        $setParameters = function(array $parameters, array $path) use($builder, &$setParameters) {
            foreach ($parameters as $parameter => $value) {
                if(is_array($value)) {
                    $setParameters($value, [...$path, $parameter]);
                } else {
                    $key = implode('.', [...$path, $parameter]);
                    $builder->setParameter($key, $value);
                }
            }
        };

        $setParameters($config, ['dakataa_two_factor_authenticator']);
	}

	public function prependExtension(
		ContainerConfigurator $container,
		ContainerBuilder $builder
	): void {
 	}

}
