<?php

namespace Dakataa\Security\TwoFactorAuthenticator;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class DakataaTwoFactorAuthenticatorBundle extends AbstractBundle
{
	const NAME = 'dakataa_2fa';

	public function configure(DefinitionConfigurator $definition): void
	{
		$definition
			->rootNode()
			->children()
				->booleanNode('enabled')->defaultValue(true)->end()
			->end();
	}

	public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
	{

		$container->parameters()->set(self::NAME, $config);
	}

	public function prependExtension(
		ContainerConfigurator $container,
		ContainerBuilder $builder
	): void {

	}
}
