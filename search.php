<?php

// Include required template file
require_once('includes/templates.php');

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

?>

<HTML>
<HEAD>
<TITLE>SentinelPlus: Advanced Reporting for WhiteHat Sentinel Vulnerabilities</TITLE>
<link rel="stylesheet" type="text/css" href="css/style.css" media="all" />
<script src="js/searchQuery.js"></script>
</HEAD>
<BODY>

<? display_header(); ?>

<div id="search">
<p>

<table class="searchOutsideTable" cellspacing="0" summary="Search Table">
<tr>
	<td class="searchTableInside">
	<table class="searchQueryTable" cellspacing="0" summary="Search Table">
	<tr>
		<td class="searchTableHeader">Search for vulnerable URLs containing:&nbsp;&nbsp;<input type="text" size="50" onkeyup="searchQuery(this.value);" name="inputText" id="inputText" /></td>
	</tr>
	</table>
	</td>
</tr>
<tr>
	<td class="searchTableInside">
		<div id="txtHint"></div>
	</td>
</tr>
</table>

</p>
</div>

</BODY>
</HTML>
