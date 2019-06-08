<?php
declare(strict_types=1);

namespace Woisks\Jwt\Middleware;


use Closure;
use Woisks\Jwt\Services\JwtService;

/**
 * Class Auth
 *
 * @package Woisks\Jwt\Middleware
 *
 * @Author  Maple Grove  <bolelin@126.com> 2019/5/17 20:38
 */
class Auth
{
    /**
     * handle 2019/5/17 20:38
     *
     * @param          $request
     * @param \Closure $next
     *
     * @return \Illuminate\Http\JsonResponse|mixed
     */
    public function handle($request, Closure $next)
    {
        $token = JwtService::jwt_parser_token();
        if (!$token) {
            return res(1001, 'param error lack token ');
        }

        $payload = JwtService::jwt_token_info();
        if (!is_array($payload)) {
            return res(1002, 'token invalid');
        }

        $iva = \Redis::get('token:' . $payload['ide'] . ':' . $payload['mac']);

        return $iva == $payload['iva'] ? $next($request) : res(1003, 'token expired');
    }


}
