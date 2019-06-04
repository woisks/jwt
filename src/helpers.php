<?php
declare(strict_types=1);

use Woisks\Jwt\JWT;

if (!function_exists('jwt_account_uid')) {


    /**
     * jwt_account_uid 2019/5/24 20:08
     *
     *
     * @return int
     */
    function jwt_account_uid(): int
    {
        return (int)jwt_token_info()['ide'];
    }
}

if (!function_exists('jwt_token_info')) {

    /**
     * jwt_token_info 2019/5/21 17:00
     *
     *
     * @return null|array
     */
    function jwt_token_info(): ?array
    {
        $info = JWT::decode_jwt(jwt_parser_token(), jwt_secret_key());
        if (is_array($info)) {
            return $info;
        }

        return null;
    }
}

if (!function_exists('jwt_secret_key')) {
    /**
     * Notes: jwt_secret_key
     *
     * @return string
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/11 21:45
     */
    function jwt_secret_key(): string
    {
        return (string)config('woisk.jwt.secret_key');
    }
}

if (!function_exists('jwt_parser_token')) {

    /**
     * jwt_parser_token
     *
     * @param string $token_name
     *
     * @return string
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/5/320:45
     */
    function jwt_parser_token(string $token_name = 'token'): string
    {
        $token = request()->server->get('HTTP_AUTHORIZATION') ?:
            request()->server->get('REDIRECT_HTTP_AUTHORIZATION');
        if ($token && preg_match('/' . 'bearer' . '\s*(\S+)\b/i', $token, $matches)) {
            return (string)$matches[1];
        }

        return (string)request()->get($token_name) ?? (string)request()->cookie($token_name);
    }
}



