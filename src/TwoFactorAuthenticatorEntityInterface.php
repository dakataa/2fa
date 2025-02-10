<?php

namespace Dakataa\Security\TwoFactorAuthenticator;

interface TwoFactorAuthenticatorEntityInterface
{

    public function getTwoFactorIdentifier(): string|int;

    public function getTwoFactorAuthenticator(): string;

    public function getTwoFactorParameters(): array|null;

}
