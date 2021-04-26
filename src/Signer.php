<?php

namespace Tleckie\UrlSigner;

use InvalidArgumentException;
use Tleckie\UrlSigner\Exception\ExpiredUriException;
use Tleckie\UrlSigner\Exception\UnsignedException;
use HttpSoft\Message\UriFactory;
use Psr\Http\Message\UriFactoryInterface;
use Psr\Http\Message\UriInterface;
use function hash;
use function http_build_query;
use function parse_str;
use function sprintf;

/**
 * Class Signer
 *
 * @package Tleckie\UrlSigner
 * @author  Teodoro Leckie Westberg <teodoroleckie@gmail.com>
 */
class Signer
{
    /** @var string */
    private string $password;

    /** @var int */
    private int $ttl;

    /** @var string|null */
    private string|null $ttlField;

    /** @var string */
    private string $hashField;

    /** @var UriFactoryInterface */
    private UriFactoryInterface $uriFactory;

    /**
     * Signer constructor.
     *
     * @param string                   $password
     * @param string                   $hashField
     * @param string|null              $ttlField
     * @param int                      $ttl
     * @param UriFactoryInterface|null $uriFactory
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $password,
        string $hashField = 'signature',
        string $ttlField = null,
        int $ttl = 0,
        UriFactoryInterface $uriFactory = null
    ) {
        $this->password = $password;
        $this->ttl = $ttl;
        $this->ttlField = $ttlField;
        $this->hashField = $hashField;
        $this->uriFactory = $uriFactory ?? new UriFactory();
        $this->checkFields();
    }

    /**
     * @param string $uri
     * @return string
     * @throws Exception
     */
    public function sign(string $uri): string
    {
        return $this->encrypt($uri);
    }

    /**
     * @param string $uri
     * @return string
     * @throws ExpiredUriException
     * @throws UnsignedException
     */
    public function validate(string $uri): string
    {
        return $this->decrypt($uri);
    }

    /**
     * @param string $uri
     * @return string
     */
    private function encrypt(string $uri): string
    {
        $uri = $this->removeParams(
            $this->uriFactory->createUri($uri)
        );

        $params = $this->parseQueryString($uri);

        if ($this->ttl > 0) {
            $params[$this->ttlField] = $this->addSeconds($this->ttl);
        }

        $uri = $uri->withQuery(
            $this->makeQueryString($params)
        );

        $params[$this->hashField] = $this->retrieveHash($uri);

        return $uri->withQuery(
            $this->makeQueryString($params)
        );
    }

    /**
     * @throws InvalidArgumentException
     */
    private function checkFields()
    {
        if (empty($this->hashField)) {
            throw new InvalidArgumentException(sprintf('Required $hashField argument'));
        }

        if ((empty($this->ttlField) && $this->ttl > 0)  || (!empty($this->ttlField) &&  $this->ttl <= 0)) {
            throw new InvalidArgumentException('Required $ttl or $ttlField argument');
        }
    }

    /**
     * @param UriInterface $uri
     * @param array        $keys
     * @return UriInterface
     */
    private function removeParams(UriInterface $uri, array $keys = []): UriInterface
    {
        $params = $this->parseQueryString($uri);
        foreach ($keys as $key) {
            if (isset($params[$key])) {
                unset($params[$key]);
            }
        }

        return $uri->withQuery($this->makeQueryString($params));
    }

    /**
     * @param UriInterface $uri
     * @return array
     */
    private function parseQueryString(UriInterface $uri): array
    {
        $params = [];

        parse_str($uri->getQuery(), $params);

        return $params;
    }

    /**
     * @param array $params
     * @return string
     */
    private function makeQueryString(array $params = []): string
    {
        return http_build_query($params);
    }

    /**
     * @param int $seconds
     * @return int
     * @throws Exception
     */
    private function addSeconds(int $seconds): int
    {
        return time() + $seconds;
    }

    /**
     * @param UriInterface $uri
     * @return string
     */
    private function retrieveHash(UriInterface $uri): string
    {
        return hash('sha1', sprintf("%s%s", $uri, $this->password));
    }

    /**
     * @param string $uri
     * @return string
     * @throws ExpiredUriException
     * @throws UnsignedException
     */
    private function decrypt(string $uri): string
    {
        $uri = $this->uriFactory->createUri($uri);
        $params = $this->parseQueryString($uri);

        $clearUri = $this->removeParams($uri, [$this->hashField]);

        if (isset($params[$this->hashField]) && $params[$this->hashField] === $this->retrieveHash($clearUri)) {
            if ($this->ttl > 0 && $this->expired($params[$this->ttlField])) {
                throw new ExpiredUriException(sprintf('Expired uri [%s]', $uri));
            }

            return $this->removeParams($clearUri, [$this->ttlField]);
        }

        throw new UnsignedException(sprintf('Decrypt failed [%s]', $uri));
    }

    /**
     * @param int $timestamp
     * @return bool
     */
    private function expired(int $timestamp): bool
    {
        return $timestamp < time();
    }
}
