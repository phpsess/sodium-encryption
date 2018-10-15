<?php

declare(strict_types=1);

namespace PHPSess\Tests;

use PHPSess\Encryption\SodiumEncryption;
use PHPSess\Exception\BadSessionContentException;
use PHPSess\Exception\UnableToDecryptException;

use PHPUnit\Framework\TestCase;

final class SodiumEncryptionTest extends TestCase
{

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::__construct
     * @covers \PHPSess\Encryption\SodiumEncryption::encryptSessionData
     * @covers \PHPSess\Encryption\SodiumEncryption::decryptSessionData
     * @covers \PHPSess\Encryption\SodiumEncryption::getEncryptionKey
     * @covers \PHPSess\Encryption\SodiumEncryption::parseEncryptedData
     */
    public function testCanDecryptEncryptedData()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $session_id = 'test_id';

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData($session_id, $data);

        $decrypted_data = $crypt_provider->decryptSessionData($session_id, $encrypted_data);

        $this->assertEquals($data, $decrypted_data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::makeSessionIdentifier
     */
    public function testIdentifierDifferentFromSid()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $session_id = 'test_id';

        $identifier = $crypt_provider->makeSessionIdentifier($session_id);

        $this->assertNotEquals($session_id, $identifier);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::encryptSessionData
     */
    public function testEncryptedDataDifferentFromData()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $session_id = 'test_id';

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData($session_id, $data);

        $this->assertNotEquals($data, $encrypted_data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::decryptSessionData
     */
    public function testCantDecryptWithWrongSessionId()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData('original_session_id', $data);

        $this->expectException(UnableToDecryptException::class);

        $crypt_provider->decryptSessionData('wrong_session_id', $encrypted_data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::decryptSessionData
     */
    public function testCanDecryptWithNewInstance()
    {
        $app_key = 'appKey';

        $crypt_provider = new SodiumEncryption($app_key);

        $session_id = 'test_id';

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData($session_id, $data);

        $new_crypt_provider = new SodiumEncryption($app_key);

        $decrypted_data = $new_crypt_provider->decryptSessionData($session_id, $encrypted_data);

        $this->assertEquals($data, $decrypted_data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::decryptSessionData
     */
    public function testCantDecryptWithWrongKey()
    {
        $crypt_provider = new SodiumEncryption('original_key');

        $session_id = 'test_id';

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData($session_id, $data);

        $new_crypt_provider = new SodiumEncryption('wrong_key');

        $this->expectException(UnableToDecryptException::class);

        var_dump($new_crypt_provider->decryptSessionData($session_id, $encrypted_data));
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::parseEncryptedData
     */
    public function testThrowExceptionWithUnparsableJson()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(BadSessionContentException::class);

        $crypt_provider->decryptSessionData('aSessionId', '{some: unparsable: json}');
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::decryptSessionData
     */
    public function testDecryptEmptyData()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $data = $crypt_provider->decryptSessionData('aSessionId', '');

        $this->assertEquals('', $data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::parseEncryptedData
     */
    public function testWrongNonce()
    {
        $data = json_encode(['data' => 'test', 'nonce' => 'wrong nonce']);

        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(BadSessionContentException::class);

        $crypt_provider->decryptSessionData('aSessionId', $data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::parseEncryptedData
     */
    public function testEmptyNonce()
    {
        $data = json_encode(['data' => 'test', 'nonce' => '']);

        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(BadSessionContentException::class);

        $crypt_provider->decryptSessionData('aSessionId', $data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::parseEncryptedData
     */
    public function testWrongData()
    {
        $data = json_encode(['data' => 'test', 'nonce' => bin2hex('aTestNonce')]);

        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(BadSessionContentException::class);

        $crypt_provider->decryptSessionData('aSessionId', $data);
    }

    /**
     * @covers \PHPSess\Encryption\SodiumEncryption::parseEncryptedData
     */
    public function testHasNoData()
    {
        $data = json_encode(['nonce' => bin2hex('aTestNonce')]);

        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(BadSessionContentException::class);

        $crypt_provider->decryptSessionData('aSessionId', $data);
    }
}
