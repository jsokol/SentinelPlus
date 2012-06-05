<?php

// Include required configuration file
require_once('includes/config.php');

// Include required template file
require_once('includes/templates.php');

// Include required functions file
require_once('includes/functions.php');

// Include required sessions file
require_once('includes/Session.class.php');

// Start session
session_start('SentinelPlus', 0, '/', 'sentinelplus.net', true);
//SessionManager::sessionStart('SentinelPlus', 0, '/', 'sentinelplus.net', true);

// Check if an API_KEY is defined
if (defined('API_KEY'))
{
	// Check for a valid key format
	if (valid_key_format('API_KEY'))
	{
		// Save the key as a session variable
		$_SESSION['key'] = encrypt(API_KEY);

		// Create the tables if they don't exist
		create_tables(API_KEY);

		// Redirect to the dashboard
		header( 'Location: dashboard.php' );
	}
}
// If an API_KEY is not defined
else
{
       	// If the key is submitted
       	if (isset($_POST['Login']))
       	{
		// Check for a valid key format
		if (valid_key_format($_POST['key']))
		{
       			// Save the key as a session variable
               		$_SESSION['key'] = encrypt($_POST['key']);

			// Create the tables if they don't exist
                       	create_tables($_POST['key']);

			// Redirect to the dashboard
			header( 'Location: configurations.php' );
		}
	}
}

?>

<HTML>
<HEAD>
<TITLE>Sentinel+</TITLE>
</HEAD>
<BODY>
<FORM action="<? echo $_SERVER['SCRIPT_NAME']; ?>" method="POST">
<TABLE>
<TR>
<TD>API Key:</TD>
<TD><INPUT name="key" type="password" autocomplete="off"  size="32" value="" /></TD>
<TD><INPUT name="Login" type="Submit" value="login" /></TD>
<TD>&nbsp;</TD>
</TR>
</TABLE>
</FORM>
</BODY>
</HTML>
