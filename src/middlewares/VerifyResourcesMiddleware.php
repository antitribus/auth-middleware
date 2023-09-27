<?php

namespace AuthApi\Middlewares;

use AuthApi\BearerToken;
use Exception;

class VerifyResourcesMiddleware
{
    public function __invoke()
    {
        try {
            // pegar dos arquivos de configuração
            $alg = '';
            $secretKey = '';
            $resource = '';

            $bearerToken = new BearerToken($alg, $secretKey, $resource) ;
            $claims = $bearerToken->getClaims();

            $method = strtolower($_SERVER['REQUEST_METHOD']);
            $path = $_SERVER['REQUEST_URI'];

            if (empty($claims->resources[$resource][$method])) {
                throw new Exception('HTTP/1.1 401 Unauthorized');
            }
            
            foreach($claims->resources[$resource][$method] as $resource) {
                if(preg_match("/{$resource}/i", $path)) {
                    return true;
                }
            }
            
            throw new Exception('HTTP/1.1 401 Unauthorized');
        } catch (Exception $e) {
            header($e->getMessage());
            exit;
        }
    }
}
