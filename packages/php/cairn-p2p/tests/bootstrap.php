<?php

declare(strict_types=1);

/**
 * Test bootstrap: load the composer autoloader (which includes a full
 * classmap for multi-class files) and explicitly load files that define
 * namespace-level functions and constants.
 */

// Load the composer autoloader (includes classmap for multi-class files)
require __DIR__ . '/../vendor/autoload.php';

// Explicitly load files that define namespace-level functions and constants
// (autoloaders only handle classes, not functions/constants)
require_once __DIR__ . '/../src/Channel.php';
require_once __DIR__ . '/../src/Server/Forward.php';
require_once __DIR__ . '/../src/Discovery/Rendezvous.php';
