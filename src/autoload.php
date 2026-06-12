<?php

declare(strict_types=1);

// Simple PSR-4 autoloader for AAGuard namespace (no external dependencies)
spl_autoload_register(function (string $class): void {
    // Only handle AAGuard namespace
    if (!str_starts_with($class, 'AAGuard\\')) {
        return;
    }

    // Convert namespace to file path: AAGuard\ClassName -> ClassName.php
    $className = substr($class, 8); // Remove "AAGuard\" prefix
    $file = __DIR__ . '/' . $className . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});
