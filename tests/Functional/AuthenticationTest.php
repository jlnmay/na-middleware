<?php 

namespace Tests\Functional; 

use JlnMay\Slim\Na\Middleware\Authentication; 

class AuthenticationTest extends \PHPUnit_Framework_TestCase
{
    public function setup()
    {
        print_r((new Authentication())());
    }

    public function testAuthentication()
    {

    }
}