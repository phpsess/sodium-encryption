<?php

declare(strict_types=1);

namespace PHPSess\Tests;

use PHPSess\Encryption\SodiumEncryption;
use PHPSess\Exception\UnknownHashAlgorithmException;
use PHPSess\Exception\UnknownEncryptionAlgorithmException;
use PHPSess\Exception\UnableToDecryptException;

use PHPUnit\Framework\TestCase;

final class SodiumEncryptionTest extends TestCase
{

    public function testIdentifierDifferentFromSid()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $session_id = 'test_id';

        $identifier = $crypt_provider->makeSessionIdentifier($session_id);

        $this->assertNotEquals($session_id, $identifier);
    }

    public function testEncryptedDataDifferentFromData()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $session_id = 'test_id';

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData($session_id, $data);

        $this->assertNotEquals($data, $encrypted_data);
    }

    public function testCanDecryptEncryptedData()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $session_id = 'test_id';

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData($session_id, $data);

        $decrypted_data = $crypt_provider->decryptSessionData($session_id, $encrypted_data);

        $this->assertEquals($data, $decrypted_data);
    }

    public function testCantDecryptWithWrongSessionId()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $data = 'test_data';

        $encrypted_data = $crypt_provider->encryptSessionData('original_session_id', $data);

        $this->expectException(UnableToDecryptException::class);

        $crypt_provider->decryptSessionData('wrong_session_id', $encrypted_data);
    }

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

    public function testThrowExceptionWithUnparsableJson()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(UnableToDecryptException::class);

        $crypt_provider->decryptSessionData('aSessionId', '{some: unparsable: json}');
    }

    public function testDecryptEmptyData()
    {
        $crypt_provider = new SodiumEncryption('appKey');

        $data = $crypt_provider->decryptSessionData('aSessionId', '');

        $this->assertEquals('', $data);
    }

    public function testWrongNonce()
    {
        $data = json_encode(['data' => 'test', 'nonce' => 'wrong nonce']);

        $crypt_provider = new SodiumEncryption('appKey');

        $this->expectException(UnableToDecryptException::class);

        $crypt_provider->decryptSessionData('aSessionId', $data);
    }
}
