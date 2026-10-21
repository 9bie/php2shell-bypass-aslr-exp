<?php
header('Content-Type: application/json');
echo json_encode([
    'version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'display_errors' => ini_get('display_errors'),
    'memory_limit' => ini_get('memory_limit'),
    'post_max_size' => ini_get('post_max_size'),
    'max_input_vars' => ini_get('max_input_vars'),
    'session.save_path' => ini_get('session.save_path'),
    'session.upload_progress.enabled' => ini_get('session.upload_progress.enabled'),
    'session.use_cookies' => ini_get('session.use_cookies'),
], JSON_PRETTY_PRINT), "\n";
