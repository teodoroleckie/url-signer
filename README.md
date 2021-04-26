# url-signer

Create secured URLs with a limited lifetime in php

[![Latest Version on Packagist](https://img.shields.io/packagist/v/tleckie/url-signer.svg?style=flat-square)](https://packagist.org/packages/tleckie/url-signer)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/teodoroleckie/url-signer/badges/quality-score.png?b=main)](https://scrutinizer-ci.com/g/teodoroleckie/url-signer/?branch=main)
[![Total Downloads](https://img.shields.io/packagist/dt/tleckie/url-signer.svg?style=flat-square)](https://packagist.org/packages/tleckie/url-signer)
[![Code Intelligence Status](https://scrutinizer-ci.com/g/teodoroleckie/url-signer/badges/code-intelligence.svg?b=main)](https://scrutinizer-ci.com/code-intelligence)
[![Build Status](https://scrutinizer-ci.com/g/teodoroleckie/url-signer/badges/build.png?b=main)](https://scrutinizer-ci.com/g/teodoroleckie/url-signer/build-status/main)

## Installation

You can install the package via composer:

```bash
composer require tleckie/url-signer
```

## Usage

```php
<?php


use Tleckie\UrlSigner\Exception\UnsignedException;
use Tleckie\UrlSigner\Exception\ExpiredUriException;
use Tleckie\UrlSigner\Signer;

// sign with expiration
$signer = new Signer('password', 'signature','ttl',3600);
$signed = $signer->sign('https://www.domain.com/path/?query=value');
// https://www.domain.com/path/?query=value&ttl=1619446592&signature=b42cb0868c6c46aad10d2a5f6e3c6503cd6b9668


try{

    $signer->validate($signed);

}catch(ExpiredUriException $exception){
    // handle expired uri

}catch(UnsignedException $exception){
    // Decrypt failed
}


// sign without expiration
$signer = new Signer('password', 'signature');
$signed = $signer->sign('https://www.domain.com/path/?query=value');
// https://www.domain.com/path/?query=value&signature=e39fe2feea843712dc2b3fa069a50c6965594f5b

```