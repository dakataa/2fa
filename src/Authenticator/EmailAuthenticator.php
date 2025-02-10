<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Authenticator;


use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\Storage\TwoFactorAuthenticatorSessionStorageInterface;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class EmailAuthenticator implements TwoFactorAuthenticatorInterface {

    public function __construct(private readonly TwoFactorAuthenticatorSessionStorageInterface $sessionStorage)
    {

    }

    public function isDispatched(TwoFactorAuthenticatorEntityInterface $entity): bool
    {

    }

    public function dispatch(TwoFactorAuthenticatorEntityInterface $entity): void
    {
        // TODO: Implement dispatch() method.
    }

    public function validate(TwoFactorAuthenticatorEntityInterface $entity, int|string $code): bool
    {
        // TODO: Implement validate() method.
    }

    public function setup(UserInterface $user):? array
    {
        return null;
    }

    public function getTTL(): int
    {
        return 60;
    }

    public function supports(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return !empty($entity->getTwoFactorEmail());
    }
}
