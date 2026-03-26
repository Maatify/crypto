<?php

use Maatify\Crypto\DX\CryptoProvider;
use Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO;

$crypto = clone $container->get(CryptoProvider::class);

$service = $crypto->context("user:email:v1");

$encrypted = $service->encrypt("hello world");

$metadata = new ReversibleCryptoMetadataDTO(
    $encrypted['result']->iv,
    $encrypted['result']->tag
);

$plain = $service->decrypt(
    $encrypted['result']->cipher,
    $encrypted['key_id'],
    $encrypted['algorithm'],
    $metadata
);
