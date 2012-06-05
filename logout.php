<?php

// Include required functions file
require_once('includes/functions.php');

// Include required sessions file
require_once('includes/Session.class.php');

// Start session
session_start('SentinelPlus', 0, '/', 'sentinelplus.net', true);
//SessionManager::sessionStart('SentinelPlus', 0, '/', 'sentinelplus.net', true);

// If we don't have a session key
if (!isset($_SESSION['key']))
{
        // Redirect to the index
        header( 'Location: index.php' );
}

// Decrypt the session key
$key = trim(decrypt($_SESSION['key']));

// Purge the vulnerability and sites tables
purge_all($key);

// Reset the session data
$_SESSION = array();

// Send a Set-Cookie to invalidate the session cookie
if (isset($_COOKIES[session_name90]))
{
	$params = session_get_cookie_params();
	setcookie(session_name(), '', 1, $params['path'], $params['domain'], $params['secure'], isset($params['httponly']));
}

// Destroy the session
session_destroy();

// Redirect to the index
header( 'Location: index.php' );

?>
