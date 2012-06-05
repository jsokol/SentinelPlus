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

/* BEGIN - IF THE REFRESH BUTTON WAS CLICKED */
if (isset($_POST['REFRESH']))
{
        // Perform a full refresh
        refresh_all($key);
}
/* END - IF THE REFRESH BUTTON WAS CLICKED */

/* BEGIN - IF THE PURGE BUTTON WAS CLICKED */
if (isset($_POST['PURGE']))
{
        // Perform a full refresh
        purge_all($key);
}
/* END - IF THE PURGE BUTTON WAS CLICKED */

?>

<HTML>
<HEAD>
<TITLE>SentinelPlus: Advanced Reporting for WhiteHat Sentinel Vulnerabilities</TITLE>
<link rel="stylesheet" type="text/css" href="css/style.css" media="all" />
<script src="js/configurations.js"></script>
</HEAD>
<BODY>

<? display_header(); ?>

<DIV ID="refreshScreen" STYLE="position:absolute;z-index:5;top:30%;left:42%;visibility:hidden">
	<TABLE BGCOLOR="#000000" BORDER="1" BORDERCOLOR="#000000" CELLPADDING="0" CELLSPACING="0" HEIGHT="100" WIDTH="150" ID="Table1">
		<TR>
			<TD WIDTH="100%" HEIGHT="100%" BGCOLOR="silver" ALIGN="CENTER" VALIGN="MIDDLE">
				<FONT FACE="Arial" SIZE="4" COLOR="blue"><B>Refreshing<br>

				Please Wait</B></FONT>

			</TD>

		</TR>

	</TABLE>

</DIV>

<DIV ID="purgeScreen" STYLE="position:absolute;z-index:5;top:30%;left:42%;visibility:hidden">
        <TABLE BGCOLOR="#000000" BORDER="1" BORDERCOLOR="#000000" CELLPADDING="0" CELLSPACING="0" HEIGHT="100" WIDTH="150" ID="Table1">
                <TR>
                        <TD WIDTH="100%" HEIGHT="100%" BGCOLOR="silver" ALIGN="CENTER" VALIGN="MIDDLE">
                                <FONT FACE="Arial" SIZE="4" COLOR="blue"><B>Purging<br>

                                Please Wait</B></FONT>

                        </TD>

                </TR>

        </TABLE>

</DIV>

<center>
<input type="button" name="REFRESH" value="REFRESH DATA FROM WHITEHAT" id="REFRESH" onClick="do_refresh1()" /><br />
<br />
<input type="button" name="PURGE" value="PURGE DATA FROM SENTINEL+" id="PURGE" onClick="do_purge1()" /><br />
</center>

</BODY>
</HTML>
