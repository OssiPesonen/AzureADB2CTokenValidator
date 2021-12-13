<?php

namespace AzureADB2CTokenValidator;

use AzureADB2CTokenValidator\Exceptions\MissingResponseException;

class File
{
    private static File $instance;

    private function __construct()
    {
    }

    public function __clone()
    {
        throw new \BadMethodCallException("__clone is not allowed");
    }

    /**
     * @return File
     */
    public static function getInstance(): File
    {
        if (!isset(self::$instance)) {
            self::$instance = new File();
        }

        return self::$instance;
    }

    /**
     * Read file from URL into a string
     *
     * @param string $url
     * @return mixed
     * @throws MissingResponseException
     */
    public function request(string $url)
    {
        $data = file_get_contents($url);

        if (!$data) {
            throw new MissingResponseException("No response from $url");
        }

        return json_decode($data);
    }
}