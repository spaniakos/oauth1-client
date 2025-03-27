<?php

namespace League\OAuth1\Client\Signature;

/**
 * HmacSha256Signature replicates HmacSha1Signature's structure
 * but uses HMAC-SHA256 for signing.
 */
class HmacSha256Signature extends Signature implements SignatureInterface
{
    use EncodesUrl;

    /**
     * Constructor matches SignatureInterface requirement.
     *
     * @param ClientCredentialsInterface $clientCredentials
     */
    public function __construct(ClientCredentialsInterface $clientCredentials)
    {
        parent::__construct($clientCredentials);
    }

    /**
     * Specifies the OAuth signature method name sent to "oauth_signature_method".
     *
     * @return string
     */
    public function method()
    {
        return 'HMAC-SHA256';
    }

    /**
     * Sign the request base string with HMAC-SHA256 and return a base64-encoded result.
     *
     * @param  string  $uri        The request URI
     * @param  array   $parameters The OAuth parameters
     * @param  string  $method     The HTTP request method (GET, POST, etc.)
     * @return string
     */
    public function sign($uri, array $parameters = [], $method = 'POST')
    {
        // Create the normalized URI and the signature base string.
        $url = $this->createUrl($uri);
        $baseString = $this->baseString($url, $method, $parameters);

        // Hash and return in base64.
        return base64_encode($this->hash($baseString));
    }

    /**
     * Actually applies the HMAC-SHA256 hash.
     *
     * @param string $string
     * @return string
     */
    protected function hash($string)
    {
        return hash_hmac('sha256', $string, $this->key(), true);
    }
}
