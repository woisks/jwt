<?php
declare(strict_types=1);

namespace Woisks\Jwt;

use Woisks\Jwt\Exceptions\InvalidException;


/**
 * Class JWT
 *
 * @package Woisks\Jwt
 * ------------------------------------------------------
 * @Author  : Maple Grove  <bolelin@126.com> 2019/5/3 22:44
 */
class JWT
{


    /**
     * encode_jwt 2019/5/14 8:51
     *
     * @param array  $payload
     * @param string $secret_key
     *
     * @return null|string
     */
    public static function encode_jwt(array $payload, string $secret_key)
    {
        try {
            return (new JWT)->encode($payload, $secret_key);
        } catch (InvalidException $e) {
            return null;
        }
    }


    /**
     * decode_jwt 2019/5/14 8:50
     *
     * @param string $token
     * @param string $secret_key
     *
     * @return null|array
     */
    public static function decode_jwt(string $token, string $secret_key)
    {
        try {
            return (new JWT)->decode($token, $secret_key);
        } catch (InvalidException $e) {
            return null;
        }
    }


    /**
     * alg
     *
     * @var string
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private $alg = 'HS256';


    /**
     * encode
     *
     * @param array  $payload
     * @param string $secret_key
     *
     * @return string
     * @throws InvalidException
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function encode(array $payload, string $secret_key)
    {
        $header = ['typ' => 'JWT', 'alg' => $this->alg];

        $segments = [];
        $segments[] = $this->base64UrlSafeEncode($this->jsonEncode($header));
        $segments[] = $this->base64UrlSafeEncode($this->jsonEncode($payload));

        $signing_input = implode('.', $segments);
        $signature = $this->sign($signing_input, $secret_key, $this->alg);
        $segments[] = $this->base64UrlSafeEncode($signature);

        return implode('.', $segments);
    }


    /**
     * decode
     *
     * @param string $token
     * @param string $secret_key
     *
     * @return array
     * @throws InvalidException
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function decode(string $token, string $secret_key)
    {
        $parts = explode('.', $token);
        if (count($parts) === 3) {

            $header = $this->jsonDecode($this->base64UrlSafeDecode($parts[0]));
            $payload = $this->jsonDecode($this->base64UrlSafeDecode($parts[1]));

            if (!$this->verify($parts[2],
                "$parts[0].$parts[1]",
                $secret_key, $header['alg'])) {
                throw new InvalidException('Signature verification failed');
            }

            return $payload;
        }

        throw new InvalidException('Wrong number of segments');
    }


    /**
     * jsonEncode
     *
     * @param array $data
     *
     * @return string
     * @throws InvalidException
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function jsonEncode(array $data)
    {
        $json = json_encode($data);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new InvalidException('Error while encoding to JSON: '
                . json_last_error_msg());
        }

        return $json;
    }


    /**
     * base64UrlSafeEncode
     *
     * @param string $str
     *
     * @return string
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function base64UrlSafeEncode(string $str)
    {
        return str_replace('=', '', strtr(base64_encode($str), '+/', '-_'));
    }


    /**
     * jsonDecode
     *
     * @param string $str
     *
     * @return array
     * @throws InvalidException
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function jsonDecode(string $str)
    {
        $data = json_decode($str, true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new InvalidException('Error while decoding to JSON: '
                . json_last_error_msg());
        }

        return $data;
    }


    /**
     * base64UrlSafeDecode
     *
     * @param string $str
     *
     * @return string
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function base64UrlSafeDecode(string $str)
    {
        if ($remainder = strlen($str) % 4) {
            $str .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($str, '-_', '+/'));
    }


    /**
     * sign
     *
     * @param string $str
     * @param string $secret_key
     * @param string $encrypt_method
     *
     * @return string
     * @throws InvalidException
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function sign(string $str, string $secret_key, string $encrypt_method)
    {
        $methods = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];
        if (empty($methods[$encrypt_method])) {
            throw new InvalidException('Algorithm not supported');
        }

        return hash_hmac($methods[$encrypt_method], $str, $secret_key, true);
    }


    /**
     * verify
     *
     * @param string $signature
     * @param string $header_payload
     * @param string $secret_key
     * @param string $encrypt_method
     *
     * @return bool
     * @throws InvalidException
     * ------------------------------------------------------
     * @Author: Maple Grove  <bolelin@126.com> 2019/5/3 22:44
     */
    private function verify(
        string $signature,
        string $header_payload,
        string $secret_key,
        string $encrypt_method
    )
    {
        $signedInput = $this->base64UrlSafeEncode(
            $this->sign("$header_payload", $secret_key, $encrypt_method)
        );

        return hash_equals($signature, $signedInput);
    }


}
