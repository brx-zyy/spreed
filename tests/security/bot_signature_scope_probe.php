<?php

declare(strict_types=1);

/**
 * Source-level regression probe for bot request signature scoping.
 *
 * This deliberately checks the current implementation without booting a
 * Nextcloud server. A passing result confirms the signature input is not
 * bound to the conversation token; it does NOT prove endpoint-level replay.
 */

$root = dirname(__DIR__, 2);
$controllerPath = $root . '/lib/Controller/BotController.php';
$servicePath = $root . '/lib/Service/ChecksumVerificationService.php';

foreach ([$controllerPath, $servicePath] as $path) {
    if (!is_file($path)) {
        fwrite(STDERR, "FAIL: required source file missing: {$path}\n");
        exit(2);
    }
}

$controller = file_get_contents($controllerPath);
$service = file_get_contents($servicePath);

$start = strpos($controller, 'protected function getBotFromHeaders(');
$end = strpos($controller, 'protected function getBotOrErrorResponse(', $start ?: 0);
if ($start === false || $end === false) {
    fwrite(STDERR, "FAIL: could not locate bot authentication method boundaries\n");
    exit(2);
}

$authMethod = substr($controller, $start, $end - $start);
$callStart = strpos($authMethod, '$this->checksumVerificationService->validateRequest(');
$callEnd = $callStart === false ? false : strpos($authMethod, ');', $callStart);

if ($callStart === false || $callEnd === false) {
    fwrite(STDERR, "FAIL: could not locate checksum validation call\n");
    exit(2);
}

$validationCall = substr($authMethod, $callStart, $callEnd - $callStart);
$usesMessageAsSignedData = str_contains($validationCall, '$message');
$bindsConversationToken = str_contains($validationCall, '$token');
$usesUnscopedHmacInput = str_contains(
    $service,
    "hash_hmac('sha256', \$random . \$data, \$secret)"
);

if (!$usesMessageAsSignedData || $bindsConversationToken || !$usesUnscopedHmacInput) {
    echo "NOT REPRODUCED: bot signature construction changed; review the implementation and update this probe.\n";
    exit(1);
}

$secret = 'ci-probe-secret';
$random = str_repeat('R', 32);
$message = 'controlled test message';
$signature = hash_hmac('sha256', $random . $message, $secret);

$roomAValid = hash_equals(hash_hmac('sha256', $random . $message, $secret), $signature);
$roomBValid = hash_equals(hash_hmac('sha256', $random . $message, $secret), $signature);

if (!$roomAValid || !$roomBValid) {
    fwrite(STDERR, "FAIL: expected identical unscoped HMAC verification result\n");
    exit(1);
}

echo "REPRODUCED: the bot message signature authenticates random + message, not the conversation token.\n";
echo "The same signature therefore verifies for either room when the same bot secret and message are used.\n";
echo "LIMITATION: source/protocol-level confirmation only; no Nextcloud HTTP endpoint or message injection was tested.\n";
