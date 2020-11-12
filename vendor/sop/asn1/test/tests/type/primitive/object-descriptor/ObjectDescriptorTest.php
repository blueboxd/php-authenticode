<?php

declare(strict_types=1);

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\NullType;
use ASN1\Type\Primitive\ObjectDescriptor;

/**
 * @group type
 * @group object-descriptor
 */
class ObjectDescriptorTest extends PHPUnit_Framework_TestCase
{
    const DESCRIPTOR = "test";
    
    public function testCreate()
    {
        $el = new ObjectDescriptor(self::DESCRIPTOR);
        $this->assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }
    
    /**
     * @depends testCreate
     *
     * @param Element $el
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_OBJECT_DESCRIPTOR, $el->tag());
    }
    
    /**
     * @depends testCreate
     *
     * @param Element $el
     * @return string
     */
    public function testEncode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertInternalType("string", $der);
        return $der;
    }
    
    /**
     * @depends testEncode
     *
     * @param string $data
     * @return ObjectDescriptor
     */
    public function testDecode($data): ObjectDescriptor
    {
        $el = ObjectDescriptor::fromDER($data);
        $this->assertInstanceOf(ObjectDescriptor::class, $el);
        return $el;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Element $ref
     * @param Element $el
     */
    public function testRecoded(Element $ref, Element $el)
    {
        $this->assertEquals($ref, $el);
    }
    
    /**
     * @depends testCreate
     *
     * @param ObjectDescriptor $desc
     */
    public function testDescriptor(ObjectDescriptor $desc)
    {
        $this->assertEquals(self::DESCRIPTOR, $desc->descriptor());
    }
    
    /**
     * @depends testCreate
     *
     * @param Element $el
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(ObjectDescriptor::class,
            $wrap->asObjectDescriptor());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $wrap->asObjectDescriptor();
    }
}
