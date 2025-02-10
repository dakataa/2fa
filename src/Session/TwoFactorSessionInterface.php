<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session;


use Serializable;

interface TwoFactorSessionInterface extends Serializable
{
    public function getIdentifier(): string|int;

    public function getData(): mixed;

    public function getTTL(): int;

}
