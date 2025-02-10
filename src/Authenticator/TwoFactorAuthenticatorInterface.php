<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Authenticator;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;
use Symfony\Component\Security\Core\User\UserInterface;

#[AutoconfigureTag('security.twoFactorAuthenticator')]
interface TwoFactorAuthenticatorInterface
{
    public function supports(TwoFactorAuthenticatorEntityInterface $entity): bool;

    public function setup(UserInterface $user): ?array;

    public function validate(TwoFactorAuthenticatorEntityInterface $entity, string|int $code): bool;
    public function dispatch(TwoFactorAuthenticatorEntityInterface $entity): void;

    public function isDispatched(TwoFactorAuthenticatorEntityInterface $entity): bool;

    public function getTTL(): int;

}
