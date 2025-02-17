<?php

namespace Dakataa\Security\TwoFactorAuthenticator;

class TwoFactorAuthenticatorEntity implements TwoFactorAuthenticatorEntityInterface
{
    public function __construct(
        private readonly string $id,
        private readonly string $authenticator,
        private readonly array|null $parameters = null,
        private readonly bool $active = false
    ) {
    }

    public function getTwoFactorIdentifier(): string|int
    {
        return $this->id;
    }

    public function getTwoFactorParameters(): array|null
    {
        return $this->parameters;
    }

    public function getTwoFactorAuthenticator(): string
    {
        return $this->authenticator;
    }

    public function isTwoFactorActive(): bool
    {
        return $this->active;
    }
}
