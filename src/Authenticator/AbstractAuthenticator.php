<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Authenticator;


use Dakataa\Security\TwoFactorAuthenticator\Notification\EmailNotification;
use Dakataa\Security\TwoFactorAuthenticator\Notification\NotificationInterface;
use Dakataa\Security\TwoFactorAuthenticator\Session\Storage\TwoFactorAuthenticatorSessionStorageInterface;
use Dakataa\Security\TwoFactorAuthenticator\Session\TwoFactorSession;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Messenger\MessageBusInterface;

abstract class AbstractAuthenticator implements TwoFactorAuthenticatorInterface
{

    public function __construct(
        private readonly TwoFactorAuthenticatorSessionStorageInterface $sessionStorage,
        private MessageBusInterface $messageBus
    ) {
    }

    public function isDispatched(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return $this->sessionStorage->has($entity);
    }

    public function dispatch(TwoFactorAuthenticatorEntityInterface $entity): void
    {
        if($this->isDispatched($entity))
            return;

        $code = mt_rand(1000, 9999);
        $session = new TwoFactorSession($code, $this->getTTL());
        $this->sessionStorage->set($entity, $session);

        // Send SMS Notification
        $this->messageBus->dispatch(new EmailNotification($entity, $code));
    }

    public function validate(TwoFactorAuthenticatorEntityInterface $entity, int|string $code): bool
    {
        if(!$this->isDispatched($entity)) {
            return false;
        }

        $session = $this->sessionStorage->get($entity);
        if($session->getData() != $code) {
            return false;
        }

        $this->sessionStorage->invalidate($entity);
        return true;
    }

    public function setup(UserInterface $user): ?array
    {
        return null;
    }

    public function getTTL(): int
    {
        return 60;
    }

    abstract public function createNotification(TwoFactorAuthenticatorEntityInterface $entity, string $code): NotificationInterface;

}
