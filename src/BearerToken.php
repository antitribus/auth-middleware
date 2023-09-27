<?php

namespace AuthApi;

use Exception;
use DateTimeImmutable;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class BearerToken
{
    private $authHeaderKeys = ['HTTP_AUTHORIZATION', 'AUTHORIZATION'];
    private $alg;
    private $secretKey;
    private $resource;
    private $token;
    private $claims;

    public function __construct($alg, $secretKey, $resource)
    {
        $this->alg = $alg;
        $this->secretKey = $secretKey;
        $this->resource = $resource;
        $this->token = $this->getTokenHeader();

        $this->extractClaims();
    }

    private function extractClaims()
    {
        $claims = JWT::decode($this->token, new Key($this->secretKey, $this->alg));
        $now = new DateTimeImmutable();

        if (
            $claims->aud !== $this->resource ||
            $claims->iss !== $this->resource ||
            $claims->nbf > $now->getTimestamp() ||
            $claims->exp < $now->getTimestamp()
        ) {
            throw new Exception('HTTP/1.1 401 Unauthorized');
        }

        $this->claims = $claims;
    }

    private function getTokenHeader()
    {
        foreach (getallheaders() as $name => $value) {
            if (in_array(strtoupper($name), $this->authHeaderKeys)) {
                return $this->getTokenHeaderValue($value);
            }
        }

        throw new Exception('HTTP/1.1 401 Unauthorized');
    }

    private function getTokenHeaderValue($token)
    {
        $isValid = $this->validateTokenHeaderFormat($token);

        if ($isValid) {
            return trim(explode($token, ' ')[1]);
        }

        throw new Exception('HTTP/1.1 401 Unauthorized');
    }

    private function validateTokenHeaderFormat($token)
    {
        return strlen($token) > 10 && str_starts_with(strtolower($token), 'bearer ');
    }

    public function getToken() {
        return $this->token;
    }

    public function getClaims() {
        return $this->claims;
    }
}
