<?php

namespace Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event;

use Symfony\Component\HttpFoundation\Response;

class TwoFactorActivateEvent extends TwoFactorSetupEvent
{
    protected Response|null $response = null;

    public function setResponse(Response|null $response): void
    {
        $this->response = $response;
    }

    public function getResponse(): Response|null
    {
        return $this->response;
    }

}
