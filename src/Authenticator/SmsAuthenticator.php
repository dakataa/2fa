<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Authenticator;


use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Notification\SmsNotification;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\Storage\TwoFactorAuthenticatorSessionStorageInterface;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\TwoFactorSession;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Security\Core\User\UserInterface;

readonly class SmsAuthenticator implements TwoFactorAuthenticatorInterface
{

    public function __construct(
        private TwoFactorAuthenticatorSessionStorageInterface $sessionStorage,
        private MessageBusInterface $messageBus
    ) {
    }

    public function setup(UserInterface $user): ?array
    {
        return null;
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

    public function dispatch(TwoFactorAuthenticatorEntityInterface $entity): void
    {
        $code = mt_rand(1000, 9999);
        $session = new TwoFactorSession($code, $this->getTTL());
        $this->sessionStorage->set($entity, $session);

        // Send SMS Notification
        $this->messageBus->dispatch(new SmsNotification($user, $code));
    }

    public function isDispatched(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return $this->sessionStorage->has($entity);
    }

    public function getTTL(): int
    {
       return 60;
    }

    public function supports(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return !empty($entity->getTwoFactorPhone());
    }
}
