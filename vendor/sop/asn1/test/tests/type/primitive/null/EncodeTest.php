<?php

declare(strict_types=1);

use ASN1\Type\Primitive\NullType;

/**
 * @group encode
 * @group null
 */
class NullEncodeTest extends PHPUnit_Framework_TestCase
{
    public function testEncode()
    {
        $el = new NullType();
        $this->assertEquals("\x5\x0", $el->toDER());
    }
}
