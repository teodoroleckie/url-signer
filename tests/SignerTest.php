<?php

namespace Tleckie\UrlSigner\Test;

use HttpSoft\Message\UriFactory;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriFactoryInterface;
use Tleckie\UrlSigner\Exception\ExpiredUriException;
use Tleckie\UrlSigner\Exception\UnsignedException;
use Tleckie\UrlSigner\Signer;

class SignerTest extends TestCase
{
    /**
     * @test
     */
    public function signDefault(): void
    {
        $uri = 'https://www.domain.com/path/?query=value';
        $expected = 'https://www.domain.com/path/?query=value&signature=1a4406a32f39e1015dad6ec2d962537f7f914fb3';

        $signer = new Signer('pass');
        $signed = $signer->sign($uri);

        static::assertEquals($expected, $signed);
    }

    /**
     * @test
     */
    public function requireHashField(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $uri = 'https://www.domain.com/path/?query=value';
        $signer = new Signer('pass', '', null);
        $signer->sign($uri);
    }

    /**
     * @test
     */
    public function requireTtlField(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $uri = 'https://www.domain.com/path/?query=value';
        $signer = new Signer('pass', 'hashField', '', 1);
        $signer->sign($uri);
    }

    /**
     * @test
     */
    public function factoryUri(): void
    {
        $uri = 'https://www.domain.com/path/?query=value';

        $uriFactoryMock = $this->createMock(UriFactoryInterface::class);

        $uriFactoryMock->expects(static::once())
            ->method('createUri')
            ->willReturn((new UriFactory())->createUri($uri));

        $signer = new Signer('pass', 'hashField', 'ttl', 1, $uriFactoryMock);
        static::assertIsString($signer->sign($uri));
    }

    /**
     * @test
     */
    public function requireTtl(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $uri = 'https://www.domain.com/path/?query=value';
        $signer = new Signer('pass', 'hashField', 'ttl');
        $signer->sign($uri);
    }

    /**
     * @test
     */
    public function requireTtlZeroValue(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $uri = 'https://www.domain.com/path/?query=value';
        $signer = new Signer('pass', 'hashField', 'ttl', 0);
        $signer->sign($uri);
    }


    /**
     * @test
     */
    public function signWithTtl(): void
    {
        $uri = 'https://www.domain.com/path/?query=value';

        $encoded = sprintf('https://www.domain.com/path/?query=value&ttl=%s', time()+2);
        $expected = sprintf(
            '%s&signature=%s',
            $encoded,
            hash('sha1', sprintf("%s%s", $encoded, 'pass'))
        );

        $signer = new Signer('pass', 'signature', 'ttl', 2);
        $signed = $signer->sign($uri);

        static::assertEquals($expected, $signed);
    }

    /**
     * @test
     */
    public function signWithOutTtl(): void
    {
        $uri = 'https://www.domain.com/path/?query=value';

        $encoded = sprintf('https://www.domain.com/path/?query=value');
        $expected = sprintf(
            '%s&signature=%s',
            $encoded,
            hash('sha1', sprintf("%s%s", $encoded, 'pass'))
        );

        $signer = new Signer('pass', 'signature');
        $signed = $signer->sign($uri);

        static::assertEquals($expected, $signed);
    }




    /**
     * @test
     */
    public function unsign(): void
    {
        $uri = 'https://www.domain.com/path/other-path/?query=value';

        $signer = new Signer('pass', 'signature', 'ttl', 1);
        $signed = $signer->sign($uri);

        static::assertEquals($uri, $signer->validate($signed));
    }

    /**
     * @test
     */
    public function unsignedExceptionWithTtl(): void
    {
        $this->expectException(UnsignedException::class);
        $uri = 'https://www.domain.com/path/other-path/?query=value';

        $signer = new Signer('pass', 'signature', 'ttl', 1);
        $signed = $signer->sign($uri);

        static::assertEquals($uri, $signer->validate($signed.'1'));
    }

    /**
     * @test
     */
    public function expired(): void
    {
        $encoded = sprintf('https://www.domain.com/path/?query=value&ttl=%s', time()-1);
        $expected = sprintf(
            '%s&signature=%s',
            $encoded,
            hash('sha1', sprintf("%s%s", $encoded, 'pass'))
        );

        $signer = new Signer('pass', 'signature', 'ttl', 1);

        $this->expectException(ExpiredUriException::class);
        $this->expectExceptionMessage(sprintf('Expired uri [%s]', $expected));

        $signer->validate($expected);
    }

    /**
     * @test
     */
    public function notExpired(): void
    {
        $encoded = sprintf('https://www.domain.com/path/?query=value&ttl=%s', time());
        $expected = sprintf(
            '%s&signature=%s',
            $encoded,
            hash('sha1', sprintf("%s%s", $encoded, 'pass'))
        );

        $signer = new Signer('pass', 'signature');
        static::assertIsString($signer->validate($expected));
    }

    /**
     * @test
     */
    public function encrypt(): void
    {
        $encoded = sprintf('https://www.domain.com/path/?query=value&ttl=%s', time()+10);
        $expected = sprintf(
            '%s&signature=%s',
            $encoded,
            hash('sha1', sprintf("%s%s", $encoded, 'pass'))
        );

        $signer = new Signer('pass', 'signature', 'ttl', 1);

        static::assertStringContainsString(sprintf('&ttl=%s', time()+1), $signer->sign($expected));
    }
}
