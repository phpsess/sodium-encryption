<?php

declare(strict_types=1);

namespace PHPSess\Encryption;

use PHPSess\Exception\BadSessionContentException;
use PHPSess\Exception\UnableToEncryptException;
use PHPSess\Interfaces\EncryptionInterface;
use PHPSess\Exception\UnableToDecryptException;
use Exception;
use stdClass;

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
     */
    public function __construct(string $appKey)
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
     * @throws BadSessionContentException
     * @param  string $sessionId   The session id.
     * @param  string $sessionData The encrypted session data.
     * @return string The decrypted session data.
     */
    public function decryptSessionData(string $sessionId, string $sessionData): string
    {
        if (!$sessionData) {
            return '';
        }

        $data = $this->parseEncryptedData($sessionData);

        $encryptionKey = $this->getEncryptionKey($sessionId);

        $decryptedData = sodium_crypto_secretbox_open($data->data, $data->nonce, $encryptionKey);

        if ($decryptedData === false) {
            $errorMessage = 'Could not decrypt the session data. Was it tampered or just corrupted?';
            throw new UnableToDecryptException($errorMessage);
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

    /**
     * @todo Create a proper class instead of using stdClass
     * @throws BadSessionContentException
     * @param string $data
     * @return stdClass
     */
    private function parseEncryptedData(string $data): stdClass
    {
        $data = json_decode($data);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $errorMessage = 'The session content is not parsable as JSON.';
            throw new BadSessionContentException($errorMessage);
        }

        if (empty($data->nonce)) {
            $errorMessage = 'The session content has no "nonce".';
            throw new BadSessionContentException($errorMessage);
        }

        if (!isset($data->data)) {
            $errorMessage = 'The session content has no "data" field.';
            throw new BadSessionContentException($errorMessage);
        }

        try {
            $nonce = sodium_hex2bin($data->nonce);
        } catch (Exception $exception) {
            $errorMessage = 'The nonce could not be converted from hexadecimal to binary.';
            throw new BadSessionContentException($errorMessage);
        }

        try {
            $data = sodium_hex2bin($data->data);
        } catch (Exception $exception) {
            $errorMessage = 'The data could not be converted from hexadecimal to binary.';
            throw new BadSessionContentException($errorMessage);
        }

        $session = new stdClass();
        $session->data = $data;
        $session->nonce = $nonce;

        return $session;
    }
}
