<?php
declare(strict_types=1);
/*
 * +----------------------------------------------------------------------+
 * |                   At all timesI love the moment                      |
 * +----------------------------------------------------------------------+
 * | Copyright (c) 2019 www.Woisk.com All rights reserved.                |
 * +----------------------------------------------------------------------+
 * |  Author:  Maple Grove  <bolelin@126.com>   QQ:364956690   286013629  |
 * +----------------------------------------------------------------------+
 */

namespace Woisks\Jwt\Services;


use Woisks\Jwt\JWT;

/**
 * Class JwtService
 *
 * @package Woisks\Jwt\Services
 *
 * @Author  Maple Grove  <bolelin@126.com> 2019/6/6 10:43
 */
class JwtService
{
    /**
     * jwt_account_uid 2019/6/6 10:43
     *
     *
     * @return int
     */
    public static function jwt_account_uid(): int
    {
        return (int)self::jwt_token_info()['ide'];
    }

    /**
     * jwt_token_info 2019/6/6 10:43
     *
     *
     * @return null|array
     */
    public static function jwt_token_info(): ?array
    {
        $info = JWT::decode_jwt(self::jwt_parser_token(), self::jwt_secret_key());

        if (is_array($info)) {
            return $info;
        }

        return null;
    }

    /**
     * jwt_parser_token 2019/6/6 10:43
     *
     * @param string $token_name
     *
     * @return string
     */
    public static function jwt_parser_token(string $token_name = 'token'): string
    {
        $token = request()->server->get('HTTP_AUTHORIZATION') ?:
            request()->server->get('REDIRECT_HTTP_AUTHORIZATION');
        if ($token && preg_match('/' . 'bearer' . '\s*(\S+)\b/i', $token, $matches)) {
            return (string)$matches[1];
        }

        return (string)request()->get($token_name) ?? (string)request()->cookie($token_name);
    }

    /**
     * jwt_secret_key 2019/6/6 10:43
     *
     *
     * @return string
     */
    public static function jwt_secret_key(): string
    {
        return (string)config('woisk.jwt.secret_key');
    }

}