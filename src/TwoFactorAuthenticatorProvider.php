<?php

namespace Dakataa\Security\TwoFactorAuthenticator;

use Dakataa\Security\TwoFactorAuthenticator\Authenticator\TwoFactorAuthenticatorInterface;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorEntityInvokingEvent;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorSetupEvent;
use Exception;
use Symfony\Component\DependencyInjection\Attribute\AutowireLocator;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class TwoFactorAuthenticatorProvider
{
    private array $entities = [];

    public function __construct(
        #[AutowireLocator('security.twoFactorAuthenticator')] private readonly ServiceLocator $serviceLocator,
        private readonly EventDispatcherInterface $eventDispatcher
    )
    {
    }

    public function getEntity(UserInterface $user): ?TwoFactorAuthenticatorEntityInterface
    {
        if (!$this->eventDispatcher->hasListeners(TwoFactorEntityInvokingEvent::class)) {
            return null;
        }

        $twoFactorInvokingEvent = new TwoFactorEntityInvokingEvent($user);
        $this->eventDispatcher->dispatch($twoFactorInvokingEvent);

        return $twoFactorInvokingEvent->getEntity();

    }

    public function getAuthenticator(
        UserInterface $user,
        string|null $optionalAuthenticator = null
    ): ?TwoFactorAuthenticatorInterface {
        $entity = $this->getEntity($user);
        $authenticator = $optionalAuthenticator ?: $entity?->getTwoFactorAuthenticator();

        if(!$authenticator) {
            return null;
        }

        if ($this->serviceLocator->has($authenticator)) {
            return $this->serviceLocator->get($authenticator);
        }

        $fqcn = __NAMESPACE__.'\\Authenticator\\'.Container::camelize($authenticator).'Authenticator';
        if ($this->serviceLocator->has($fqcn)) {
            return $this->serviceLocator->get($fqcn);
        }

        if (!class_exists($fqcn)) {
            throw new Exception('Two Factor Authenticator class "'.$fqcn.'" not found');
        }

        return new $fqcn;
    }

    public function setupProvider(UserInterface $user, string $authenticatorName): TwoFactorAuthenticatorEntityInterface
    {
        if(!$this->eventDispatcher->hasListeners(TwoFactorSetupEvent::class)) {
            throw new Exception('Two Step Authenticator has not provided Setup handler to process.');
        }

        $authenticator = $this->getAuthenticator($user, $authenticatorName);
        $parameters = $authenticator->setup($user);

        $entity = new TwoFactorAuthenticatorEntity(
            $user->getUserIdentifier(),
            $authenticatorName,
            $parameters
        );

        $event = new TwoFactorSetupEvent($user, $entity);
        $this->eventDispatcher->dispatch($event);

        return $entity;
    }
}
