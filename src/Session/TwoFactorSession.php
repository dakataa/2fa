<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Session;

use Ramsey\Uuid\Uuid;

class TwoFactorSession implements TwoFactorSessionInterface
{
    private readonly string $id;

    public function __construct(private mixed $data = null, private int $ttl = 5) {
        $this->id = Uuid::uuid4()->toString();
    }

    public function getIdentifier(): string|int
    {
        return $this->id;
    }

    public function getData(): mixed {
        return $this->data;
    }

    public function getTTL(): int
    {
        return $this->ttl;
    }

    public function setTTL(int $ttl): void
    {
        $this->ttl = $ttl;
    }

    public function setData(mixed $data): void
    {
        $this->data = $data;
    }

    public function serialize(): array
    {
        return $this->__serialize();
    }

    public function unserialize($data): void
    {
       $this->__unserialize($data);
    }

    public function __serialize(): array
    {
        return [
            $this->id,
            $this->data,
            $this->ttl
        ];
    }

    public function __unserialize(array $data): void
    {
        [$this->id, $this->data, $this->ttl] = $data;
    }
}
