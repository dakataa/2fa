# Symfony 2FA (Two Factor Authenticator)
This package helps you to enable Two Factor Authenticator
for users over your current authenticator.
Providing SMS, Email and OTP (TOTP / HOTP).
Easy way to implement Custom Auth Code provider.

#### To get started, install the bundle:

```shell
composer require dakataa/2fa
```

#### Configuration:

```yaml
### config/packages/dakataa_2fa.yaml
dakataa_two_factor_authenticator:
  enabled: true
  code_parameter: code
  username_parameter: username
  form_path: auth_2fa_form
  check_path: auth_2fa_check
  target:
    parameter: _target
    default_path: /
```

### Create Controller to handle form & check paths
```php
<?php

// ....

#[Route('/2fa')]
class TwoFactorController extends AbstractController
{
    #[Route('/form', name: 'auth_2fa_form')]
    public function form(AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('auth/2fa/form.html.twig', [
            'error' => $authenticationUtils->getLastAuthenticationError(),
        ]);
    }

    #[Route('/check', name: 'auth_2fa_check')]
    public function check(): Response
    {
        throw new Exception('Please setup  2FA key "check_path" in configuration.');
    }

	#[IsGranted('ROLE_USER')]
    #[Route('/setup/{authenticator}', name: "auth_2fa_setup")]
    public function setup(#[CurrentUser] UserInterface $user, TwoFactorAuthenticatorProvider $twoFactorAuthenticatorProvider, string $authenticator = null): Response
    {
        if($authenticator) {
            $entity = $twoFactorAuthenticatorProvider->setupProvider($user, $authenticator);
            $twoFactorAuthenticatorProvider->getAuthenticator($user)?->dispatch($entity);

            return match($authenticator) {
                'otp' =>  $this->render('auth/2fa/setup_otp.html.twig', [
                    'parameters' => $entity->getTwoFactorParameters()
                ]),
                default => new RedirectResponse($this->generateUrl('auth_2fa_form'))
            };
        }

        return $this->render('auth/2fa/setup.html.twig');
    }
}
```

### Views

auth/2fa/form.html.twig
```html & twig
{% extends 'base.html.twig' %}
{% block body %}
<h3>2FA</h3>
{% if error %}
<div>{{ error.message|trans(error.messageData, 'security') }}</div>
{% endif %}
<p>Please provide code you receive.</p>
<form method="POST" action="{{ url('auth_2fa_check') }}">
    <label>
        Code
        <input type="text" name="code" />
    </label>
    <button type="submit">Submit</button>
</form>
{% endblock %}

```

auth/2fa/setup.html.twig
```html & twig
{% extends 'base.html.twig' %}
{% block body %}
<h3>Select 2FA Authenticator</h3>
<ul>
    <li>
        <a href="{{ url('auth_2fa_setup', { authenticator: 'otp' }) }}">OTP Authenticator (Google Auth, etc.)</a>
    </li>
    <li>
        <a href="{{ url('auth_2fa_setup', { authenticator: 'sms' }) }}">SMS</a>
    </li>
    <li>
        <a href="{{ url('auth_2fa_setup', { authenticator: 'email' }) }}">Email</a>
    </li>
</ul>
{% endblock %}
```

auth/2fa/setup_otp.html.twig
```html & twig
{% extends 'base.html.twig' %}
{% block body %}
<h3>OTP</h3>
<div>
    <strong>Secret:</strong>
    <code>
        {{ parameters.secret }}
    </code>
    <p>
        <strong>Barcode:</strong>
        You have to generate BARCODE
        contains this value {{ parameters.provisioningUri }}
    </p>
</div>
<a href="{{ url('auth_2fa_form') }}">Activate</a>
{% endblock %}
```

## Setup Event Handlers
Example with temporary cache storage. We should store Two Factor User information in current cache storage.
Right way is to store it in database user table or separate table related to user.
```php
<?php

// ...

class TwoFactorEventHandler
{

    public function __construct(private readonly CacheItemPoolInterface $twoFactorTemporaryStorage)
    {

    }

    #[AsEventListener(event: TwoFactorEntityInvokingEvent::class)]
    public function onTwoFactorEntityInvokingEvent(TwoFactorEntityInvokingEvent $event): void
    {
        $user = $event->getUser();
        $cacheKey = sha1($user->getUserIdentifier());
        if(!$this->twoFactorTemporaryStorage->hasItem($cacheKey)) {
            return;
        }

        $data = $this->twoFactorTemporaryStorage->getItem($cacheKey)->get();
        if(empty($data) || !is_array($data)) {
            return;
        }

        [
            'authenticator' => $authenticator,
            'parameters' => $parameters,
            'active' => $active
        ] = $data + [
            'authenticator' => null,
            'parameters' => null,
            'active' => false
        ];


        if(!$authenticator) {
            return;
        }

        $entity = new TwoFactorAuthenticatorEntity($user->getUserIdentifier(), $authenticator, $parameters, $active);

        $event->setEntity($entity);
    }

    #[AsEventListener(event: TwoFactorSetupEvent::class)]
    public function onTwoFactorSetupEvent(TwoFactorSetupEvent $event): void
    {
        $cacheKey = sha1($event->getUser()->getUserIdentifier());
        $cacheItem = $this->twoFactorTemporaryStorage->getItem($cacheKey);
        $cacheItem->set([
            'authenticator' => $event->getEntity()->getTwoFactorAuthenticator(),
            'parameters' => $event->getEntity()->getTwoFactorParameters(),
            'active' => false
        ]);
        $this->twoFactorTemporaryStorage->save($cacheItem);
    }

    #[AsEventListener(event: TwoFactorActivateEvent::class)]
    public function onTwoFactorActivateEvent(TwoFactorActivateEvent $event): void
    {
        $cacheKey = sha1($event->getUser()->getUserIdentifier());
        $cacheItem = $this->twoFactorTemporaryStorage->getItem($cacheKey);
        if(empty($data = $cacheItem->get())) {
            return;
        }

        $data = [...$data, 'active' => true];
        $cacheItem->set($data);
        $this->twoFactorTemporaryStorage->save($cacheItem);

        $event->setResponse(new RedirectResponse('/'));
    }

}
```



## Events

| Event                               | Description                                                                                                                                                        | 
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TwoFactorEntityInvokingEvent::class | This event is triggered when bundle need information about user 2FA. You have to Provide TwoFactorAuthenticatorEntity object containing authenticator information. |
| TwoFactorSetupEvent::class          | This event is triggered on user authenticator 2FA setup. You receive authenticator parameters for the user and you have to save it for future use.                 |
| TwoFactorActivateEvent::class       | This event is triggered after successful 2FA code validation on SETUP.                                                                                             |

## Messages
This bundle use Symfony Messenger. We have two notifications which you have to handle.

| Notification             | Description        |
|--------------------------|--------------------|
| SmsNotification::class   | Contains Auth Code |
| EmailNotification::class | Contains Auth Code |

### How to handle notifications
```php
<?php

namespace App\Component\MessageHandler;

use Dakataa\Security\TwoFactorAuthenticator\Notification\EmailNotification;
use Dakataa\Security\TwoFactorAuthenticator\Notification\SmsNotification;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

class TwoFactorMessageHandler extends AbstractController
{
    #[AsMessageHandler]
    public function smsNotificationHandler(SmsNotification $message)
    {
       // Send SMS with code
       // $message->getCode();
    }

    #[AsMessageHandler]
    public function emailNotificationHandler(EmailNotification $message)
    {
       // Send Email with code
       // $message->getCode();
    }

}
```
