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
  form_path: /2fa/form
  check_path: /2fa/check
```

### Create Controller to handle form & check paths
```php
class TwoFactorController extends AbstractController
{
    #[Route('/2fa/form')]
    public function form(): Response
    {
        return $this->render('2fa/form.html.twig');
    }

    #[Route('/2fa/check')]
    public function check(): Response
    {
        return new Response('2FA Check');
    }

    #[Route('/2fa/setup/{authenticator}')]
    public function setup(#[CurrentUser] UserInterface $user, TwoFactorAuthenticatorProvider $twoFactorAuthenticatorProvider, string $authenticator = null): Response
    {
        if($authenticator) {
	        $entity = $twoFactorAuthenticatorProvider->setupProvider($user, $authenticator);
	        $twoFactorAuthenticatorProvider->getAuthenticator($user)?->dispatch($entity);

	        return match($authenticator) {
	            'otp' =>  $this->render('2fa/setup_otp.html.twig', [
	                'parameters' => $entity->getTwoFactorParameters()
	            ]),
	            default => new RedirectResponse('/2fa/form')
	        };
        }

        return $this->render('2fa/setup.html.twig');
    }
}
```

### Views

2fa/form.html.twig
```html & twig
<h3>2FA</h3>
<p>Please provide code from {{ authenticator }}.</p>
<form method="POST" action="/2fa/check">
	<input type="text" name="code" />
	<button type="submit">Submit</button>
</form>
```

2fa/setup.html.twig
```html & twig
<h3>Select 2FA Authenticator</h3>
<ul>
	<li>
		<a href="/2fa/setup/otp">OTP Authenticator (Google Auth, etc.)</a>
	</li>
	<li>
		<a href="/2fa/setup/sms">SMS</a>
	</li>
	<li>
		<a href="/2fa/setup/email">Email</a>
	</li>
</ul>
```

2fa/setup_otp.html.twig
```html & twig
<h3>OTP</h3>
<div>
	<p>
		Secret: {{ parameters.secret }}
	</p>
	<p>
		<strong>Barcode:</strong>
		You have to generate BARCODE
		contains this value {{ parameters.provisioningUri }}
	</p>
</div>
```

## Setup Event Handlers
```php
<?php

namespace App\Component\Security\EventHandler;

use App\Entity\User;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorActivateEvent;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorEntityInvokingEvent;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorSetupEvent;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntity;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

class TwoFactorEventHandler
{

    public function __construct(private EntityManagerInterface $entityManager)
    {

    }

    #[AsEventListener(event: TwoFactorEntityInvokingEvent::class)]
    public function onTwoFactorEntityInvokingEvent(TwoFactorEntityInvokingEvent $event): void
    {
        /** @var User $user */
        $user = $event->getUser();
        ['authenticator' => $authenticator, 'parameters' => $parameters, 'active' => $active] = ($user->getTwoFactor() ?: []) + ['authenticator' => null, 'parameters' => null];
        if(!$authenticator) {
            return;
        }

        $entity = new TwoFactorAuthenticatorEntity($user->getUserIdentifier(), $authenticator, $parameters, $active);

        $event->setEntity($entity);
    }

    #[AsEventListener(event: TwoFactorSetupEvent::class)]
    public function onTwoFactorSetupEvent(TwoFactorSetupEvent $event): void
    {
        /** @var User $user */
        $user = $event->getUser();
        $user->setTwoFactor([
            'authenticator' => $event->getEntity()->getTwoFactorAuthenticator(),
            'parameters' => $event->getEntity()->getTwoFactorParameters(),
            'active' => false,
        ]);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

    }

    #[AsEventListener(event: TwoFactorActivateEvent::class)]
    public function onTwoFactorActivateEvent(TwoFactorActivateEvent $event): void
    {
        /** @var User $user */
        $user = $event->getUser();
        if(!$user->getTwoFactor())
            {throw new \Exception('Two Factor is not setup for this user');}

        $user->setTwoFactor([
            ...$user->getTwoFactor(),
            'active' => true,
        ]);

        $this->entityManager->persist($user);
        $this->entityManager->flush();
    }

}

```



## Events

| Event                               | Description                                                                                                                                                        | 
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TwoFactorEntityInvokingEvent::class | This event is triggered when bundle need information about user 2FA. You have to Provide TwoFactorAuthenticatorEntity object containing authenticator information. |
| TwoFactorSetupEvent::class          | This event is triggered on user authenticator 2FA setup. You receive authenticator parameters for the user and you have to save it for future use.                 |
| TwoFactorActivateEvent::class       | This event is triggered after successfull 2FA code validation on SETUP.                                                                                            |

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
