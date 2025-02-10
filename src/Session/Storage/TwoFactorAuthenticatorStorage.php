<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\Storage;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Session\TwoFactorSessionInterface;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use DateInterval;
use Exception;
use Psr\Cache\CacheItemPoolInterface;

class TwoFactorAuthenticatorStorage implements TwoFactorAuthenticatorSessionStorageInterface
{

    public function __construct(private readonly CacheItemPoolInterface $twoFactorAuthenticatorCache)
    {
    }

    public function has(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return $this->twoFactorAuthenticatorCache->hasItem($entity->getTwoFactorIdentifier());
    }

    public function get(TwoFactorAuthenticatorEntityInterface $entity): TwoFactorSessionInterface
    {
        if (!$this->has($entity)) {
            throw new Exception('Missing 2FA Session.');
        }

        $cacheItem = $this->twoFactorAuthenticatorCache->getItem($entity->getTwoFactorIdentifier());
        $data = $cacheItem->get();
        if (false === $data instanceof TwoFactorSessionInterface) {
            throw new Exception('Invalid Session');
        }

        return $data;
    }


    public function set(
        TwoFactorAuthenticatorEntityInterface $entity,
        TwoFactorSessionInterface $session
    ): void {

        $item = $this->twoFactorAuthenticatorCache->getItem($entity->getTwoFactorIdentifier());

        $item->set($session)
            ->expiresAfter(new DateInterval(sprintf('PT%dS', $session->getTTL())));

        $this
            ->twoFactorAuthenticatorCache
            ->save($item);
    }

    public function invalidate(TwoFactorAuthenticatorEntityInterface $entity): void
    {
        $this->twoFactorAuthenticatorCache->deleteItem($entity->getTwoFactorIdentifier());
    }
}
