<?php
declare(strict_types=1);

/**
 * +----------------------------------------------------------------------+
 * |                   At all timesI love the moment                      |
 * +----------------------------------------------------------------------+
 * | Copyright (c) 2019 www.Woisk.com All rights reserved.                |
 * +----------------------------------------------------------------------+
 * | This source file is subject to version 2.0 of the Apache license,    |
 * | that is bundled with this package in the file LICENSE, and is        |
 * | available through the world-wide-web at the following url:           |
 * | www.apache.org/licenses/LICENSE-2.0.html                             |
 * +----------------------------------------------------------------------+
 * |  Author:  Maple Grove  <bolelin@126.com>   QQ:364956690   286013629  |
 * +----------------------------------------------------------------------+
 */
return [
    /**
     * JWT密钥
     */
    'secret_key'  => env('JWT_KEY', ''),

    /**
     * JWT
     * ide 用户唯一识别UID
     * iva 当前此次的登陆记录ID
     * mac redis识别ID->key
     */


    /**
     * 默认 token有效期 单位分钟(默认7天)
     * 预防用户长时间处于登录状态
     */
    'expire_time' => 10080

];