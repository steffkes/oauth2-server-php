<?php

class OAuth2_ServerFactoryTest extends PHPUnit_Framework_TestCase
{
    public function testAddingStorageWithValidKeyOnlySetsThatKey()
    {
        if (version_compare(phpversion(), '5.3', '<')) {
            // cannot run this test in 5.2
            return $this->markTestSkipped('Requires php 5.3 or higher');
        }

        $factory = new OAuth2_ServerFactory();
        $factory->addStorage($this->getMock('OAuth2_Storage_Memory'), 'access_token');

        $reflection = new ReflectionClass($factory);
        $prop = $reflection->getProperty('storages');
        $prop->setAccessible(true);

        $storages = $prop->getValue($factory); // get the private "storages" property

        $this->assertEquals(1, count($storages));
        $this->assertTrue(isset($storages['access_token']));
        $this->assertFalse(isset($storages['authorization_code']));
    }
}
