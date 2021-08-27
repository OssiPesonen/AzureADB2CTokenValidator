<?php

namespace AzureADB2CTokenValidator;

class PublicKey {
    public $kid;
    public $nbf;
    public $use;
    public $kty;
    public $e;
    public $n;

    public function __construct(array $args) {
        $this->validateArgs($args);

        foreach ($args as $k => $v) {
            $this->{$k} = $v;
        }
    }

    private function validateArgs(array $args) {
        $vars = get_class_vars(__CLASS__);

        foreach($vars as $k => $v) {
            if (!isset($args[$k])) {
                throw new \InvalidArgumentException("Missing property $k in arguments");
            }
        }
    }
}