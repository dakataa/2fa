<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\Storage;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\TwoFactorSessionInterface;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;

interface TwoFactorAuthenticatorSessionStorageInterface {

    public function has(TwoFactorAuthenticatorEntityInterface $entity): bool;

    public function get(TwoFactorAuthenticatorEntityInterface $entity): TwoFactorSessionInterface;
    public function set(TwoFactorAuthenticatorEntityInterface $entity, TwoFactorSessionInterface $session): void;

    public function invalidate(TwoFactorAuthenticatorEntityInterface $entity): void;
}
