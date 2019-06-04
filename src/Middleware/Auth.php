<?php
declare(strict_types=1);

namespace Woisks\Jwt\Middleware;


use Closure;

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
        $token = jwt_parser_token();
        if (!$token) {
            return res(1001, 'param error lack token ');
        }

        $payload = jwt_token_info();
        if (!is_array($payload)) {
            return res(401, 'Token Invalid');
        }

        $iva = \Redis::get('token:' . $payload['ide'] . ':' . $payload['mac']);

        return $iva == $payload['iva'] ? $next($request) : res(401, 'Token Expired');
    }


}
