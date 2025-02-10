<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\EventHandler\Listener;


use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorProvider;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

#[AsEventListener(event: AuthenticationTokenCreatedEvent::class, method: 'onAuthenticationTokenCreatedEvent')]
#[AsEventListener(event: LoginSuccessEvent::class, method: 'onLoginSuccessEvent')]
final class TwoFactorAuthenticatorListener
{
    public function __construct(
        private readonly TwoFactorAuthenticatorProvider $twoFactorProvider
    ) {

    }

    public function onAuthenticationTokenCreatedEvent(AuthenticationTokenCreatedEvent $event)
    {
//        dd($event);
    }

    public function onLoginSuccessEvent(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        $request = $event->getRequest();

        $twoFactorAuthenticator = $this->twoFactorProvider->getAuthenticator($user);
        $twoFactorEntity = $this->twoFactorProvider->getEntity($user);
        if ($twoFactorAuthenticator) {
            try {
                if (!$twoFactorAuthenticator->supports($twoFactorEntity)) {
                    $this->twoFactorProvider->setupProvider($user);
                    throw new BadCredentialsException('Two Factor Authentication not supported.');
                }

                if ($twoFactorAuthenticator->isDispatched($twoFactorEntity) && $request->getPayload()->has('code')) {
                    if (!$twoFactorAuthenticator->validate($twoFactorEntity, $request->getPayload()->getString('code'))) {
                        throw new BadCredentialsException(
                            'Invalid Two Factor Credentials. Please provide a valid Auth code.'
                        );
                    }
                } else {
                    $twoFactorAuthenticator->dispatch($twoFactorEntity);

                    throw new BadCredentialsException('Two Factor Authentication required.');
                }
            } catch (BadCredentialsException $e) {
                $event->setResponse(new JsonResponse([
                    'error' => $e->getMessage(),
                    'requirements' => [
                        'twoFactorAuthenticator' => [
                            'authenticator' => $twoFactorEntity->getTwoFactorAuthenticator(),
                            'fields' => [
                                'code',
                            ],
                        ],
                    ],
                ]));
            }
        } else {
            $this->twoFactorProvider->setupProvider($user, 'otp');
        }
    }

}
