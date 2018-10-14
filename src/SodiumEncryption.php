<?php

declare(strict_types=1);

namespace PHPSess\Encryption;

use PHPSess\Interfaces\EncryptionInterface;
use PHPSess\Exception\UnableToDecryptException;
use Exception;

class SodiumEncryption implements EncryptionInterface
{

    /**
     * @var string $appKey The hashed app key.
     */
    private $appKey;

    /**
     * SodiumEncryption constructor.
     *
     * @param  string $appKey              Defines the App Key.
     * @param  string $hashAlgorithm       Defines the algorithm used to create hashes.
     * @param  string $encryptionAlgorithm Defines the algorithm to encrypt/decrypt data.
     */
    public function __construct(string $appKey, string $hashAlgorithm = 'sha512', string $encryptionAlgorithm = 'aes128')
    {
        $binaryHash = sodium_crypto_generichash($appKey);
        $this->appKey = sodium_bin2hex($binaryHash);
    }

    /**
     * Makes a session identifier based on the session id.
     *
     * @param  string $sessionId The session id.
     * @return string The session identifier.
     */
    public function makeSessionIdentifier(string $sessionId): string
    {
        $hashContent = $sessionId . $this->appKey;
        $binaryHash = sodium_crypto_generichash($hashContent);
        return sodium_bin2hex($binaryHash);
    }

    /**
     * Encrypts the session data.
     *
     * @throws Exception
     * @param  string $sessionId   The session id.
     * @param  string $sessionData The session data.
     * @return string The encrypted session data.
     */
    public function encryptSessionData(string $sessionId, string $sessionData): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $encryptionKey = $this->getEncryptionKey($sessionId);

        $encryptedBinary = sodium_crypto_secretbox($sessionData, $nonce, $encryptionKey);

        return (string) json_encode([
            'data' => sodium_bin2hex($encryptedBinary),
            'nonce' => sodium_bin2hex($nonce)
        ]);
    }

    /**
     * Decrypts the session data.
     *
     * @throws UnableToDecryptException
     * @param  string $sessionId   The session id.
     * @param  string $sessionData The encrypted session data.
     * @return string The decrypted session data.
     */
    public function decryptSessionData(string $sessionId, string $sessionData): string
    {
        if (!$sessionData) {
            return '';
        }

        $encryptedData = json_decode($sessionData);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new UnableToDecryptException();
        }

        try {
            $nonce = sodium_hex2bin($encryptedData->nonce);
            $data = sodium_hex2bin($encryptedData->data);
        } catch (Exception $exception) {
            throw new UnableToDecryptException();
        }

        $encryptionKey = $this->getEncryptionKey($sessionId);

        $decryptedData = sodium_crypto_secretbox_open($data, $nonce, $encryptionKey);

        if ($decryptedData === false) {
            throw new UnableToDecryptException();
        }

        return $decryptedData;
    }

    /**
     * Calculates the key to be used in the session encryption.
     *
     * @param  string $sessionId Id of the session
     * @return string Encryption key
     */
    private function getEncryptionKey(string $sessionId): string
    {
        $hashContent = $this->appKey . $sessionId;
        $binaryHash = sodium_crypto_generichash($hashContent);
        $hash = sodium_bin2hex($binaryHash);
        return substr($hash, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }
}
