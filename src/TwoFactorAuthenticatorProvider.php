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

    public function __construct(
        #[AutowireLocator('security.twoFactorAuthenticator')] private readonly ServiceLocator $serviceLocator,
        private readonly EventDispatcherInterface $eventDispatcher
    )
    {
    }

    public function getEntity(UserInterface $user): ?TwoFactorAuthenticatorEntityInterface
    {
        $twoFactorInvokingEvent = new TwoFactorEntityInvokingEvent($user);
        $this->eventDispatcher->dispatch($twoFactorInvokingEvent);

        if(!$this->eventDispatcher->hasListeners(TwoFactorEntityInvokingEvent::class)) {
            throw new Exception('TwoFactorEntityInvokingEvent::class has no handler registered.');
        }

        return $twoFactorInvokingEvent->getEntity();
    }

    public function getAuthenticator(
        UserInterface $user,
        string|null $optionalAuthenticator = null
    ): ?TwoFactorAuthenticatorInterface {
        $entity = $this->getEntity($user);
        $authenticator = $entity?->getTwoFactorAuthenticator() ?: $optionalAuthenticator;

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

    public function setupProvider(UserInterface $user, string $authenticator = null): void
    {
        $parameters = $this->getAuthenticator($user, $authenticator)->setup($user);

        $event = new TwoFactorSetupEvent($user, new TwoFactorAuthenticatorEntity($user->getUserIdentifier(), 'otp', $parameters));

        $this->eventDispatcher->dispatch($event);

        if(!$this->eventDispatcher->hasListeners(TwoFactorSetupEvent::class)) {
            throw new Exception('Two Step Authenticator has not provided Setup handler to process.');
        }

    }
}
