<?php

// Include required functions file
require_once('../includes/functions.php');

// Include required sessions file
require_once('../includes/Session.class.php');

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

// If a query has been submitted and it is not empty
if (isset($_GET['q']) && $_GET['q'] != "")
{
        $q=$_GET["q"];

	// Get the list of Sentinel sites from the database
	search_vulnerable_urls($key, $q);
}

?> 
