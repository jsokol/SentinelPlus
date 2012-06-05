<?php
/*******************************************
 * WhiteHat Sentinel Vulnerability Tracker *
 * Created by Josh Sokol 2010-11-09        *
 * Requires a MySQL database specified in  *
 * the config.php file with a table named  *
 * "vulnerabilities" with the following    *
 * fields:                                 *
 * id - int(10)                            *
 * class - varchar(100)                    *
 * status - varchar(8)                     *
 * severity - int(2)                       *
 * threat - int(2)                         *
 * score - int(2)                          *
 * found - timestamp                       *
 * opened - timestamp                      *
 * closed - timestamp                      *
 * url - varchar(100)                      *
 * href - varchar(100)                     *
 * site - varchar(100)                     *
 * retest_state - varchar(50)              *
 *******************************************/

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

// Set the site value if we have one
if (isset($_POST['site']))
{
	$selected_site = $_POST['site'];
}

// Set the class value if we have one
if (isset($_POST['class']))
{
        $selected_class = $_POST['class'];
}

?>

<HTML>
<HEAD>
<TITLE>SentinelPlus: Advanced Reporting for WhiteHat Sentinel Vulnerabilities</TITLE>
<link rel="stylesheet" type="text/css" href="css/style.css" media="all" />
</HEAD>
<BODY>

<? display_header(); ?>

<form action="" method="POST">
Site:&nbsp;&nbsp;
<select name="site" onChange="this.form.submit();">

<option value="ALL SITES"<? if (!isset($_POST['site'])) echo " selected" ?>>ALL SITES</option>
<option value="PRODUCTION"<? if ($_POST['site'] == "PRODUCTION") echo " selected" ?>>PRODUCTION</option>
<option value="TEST"<? if ($_POST['site'] == "TEST") echo " selected" ?>>TEST</option>
<?

// If no site was posted, default is ALL SITES
if (!isset($_POST['site'])) $selected_site = "ALL SITES";

// Get the list of sites
$sites = get_sites($key);

// For each site in the list
foreach ($sites as $site)
{
        echo "<option value=\"" . $site['siteid'] . "\"";
        if ($_POST['site'] == $site['siteid']) echo " selected";
        echo ">" . $site['sitelabel'] . "</option>\n";
}

?>

</select>
<br />
Class:&nbsp;&nbsp;
<select name="class" onChange="this.form.submit();">
<option value="ALL CLASSES"<? if (!isset($_POST['class'])) echo " selected" ?>>ALL CLASSES</option>

<?
// If no class was posted, default is ALL CLASSES
if (!isset($_POST['class'])) $selected_class = "ALL CLASSES";

// Get the unique list of all classes of vulnerabilities
$classes = get_classes($key);

// For each class in the list
foreach ($classes as $class)
{
        echo "<option value=\"" . $class['class'] . "\"";
        if ($_POST['class'] == $class['class']) echo " selected";
        echo ">" . $class['class'] . "</option>\n";
}

?>

</select>
</form>

<!-- LIST URLS -->
<div id="urls">
<?
        // Print the list of URLs with vulnerabilities
        $vulnerable_urls = list_vulnerable_urls($key, $selected_site, $selected_class);
?>
</div>

</BODY>
</HTML>
