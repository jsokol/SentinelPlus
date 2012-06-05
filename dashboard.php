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

// Get the list of vulnerability classes
$classes = get_classes($key);

// Set the site value if we have one
if (isset($_POST['site']))
{
	$selected_site = $_POST['site'];
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
</form>

<!-- BEGIN VULNERABILITY TRENDS -->
<?
	// Get the vulnerability trend array
	$vulnerability_trend_array = get_vulnerability_trend_array($key, $selected_site);

	// Create table to hold trend information
	echo "<table>\n";
	echo "<tr>\n";
	echo "<td>\n";

	// Print the vulnerability trend table without a footer
	display_array_results("Open Vulnerabilities Over Time", false, $vulnerability_trend_array);

	// Pop the first element off the trend array
	array_shift($vulnerability_trend_array[4]);

	// Get the trend array
	$trends = $vulnerability_trend_array[4];

	// Create table to hold trend information
	echo "</td>\n";
	echo "<td>\n";

	// Print the trend summary
	display_trend_summary("Cumulative Vulnerability Trend", $trends);

	// Create table to hold trend information
	echo "</td>\n";
	echo "</tr>\n";
	echo "</table>\n";

	// Pop the first element off the arrays
	array_shift($vulnerability_trend_array[0]);
	array_shift($vulnerability_trend_array[3]);

	// Get the date and total arrays
	$dates = $vulnerability_trend_array[0];
	$totals = $vulnerability_trend_array[3];

	// Graph the open vulnerabilities over time
	graph_data("Open Vulnerabilities Over Time on NI.com", "trend-vulnerabilities.png", $dates, $totals);
?>
<!-- END VULNERABILITY TRENDS -->

<!-- BEGIN VULNERABILITY CLASSES -->
<?
	// Get the classes array
	$vulnerability_classes_array = get_vulnerability_class_array($key, $selected_site);

        // Create table to hold class information
        echo "<table>\n";
        echo "<tr>\n";
        echo "<td>\n";

	// Print the classes summary
	display_array_results("Current Top Vulnerability Classes", false, $vulnerability_classes_array);

	// Pop the first element off the array
	array_shift($vulnerability_classes_array);

	// Create the trend array
	foreach ($vulnerability_classes_array as $row)
	{
		$class_trends[] = $row[2];
	}

        // Create table to hold trend information
        echo "</td>\n";
        echo "<td>\n";

        // Print the trend summary
        display_trend_summary("Vulnerability Trend Since Last Release", $class_trends);

        // Create table to hold trend information
        echo "</td>\n";
        echo "</tr>\n";
        echo "</table>\n";

	// Create the legend array
	foreach ($vulnerability_classes_array as $row)
	{
		$legend[] = $row[0];
	}

	// Create the data array
	foreach ($vulnerability_classes_array as $row)
        {
                $data[] = $row[1];
        }

	// Place a pie chart of the current top vulnerability classes
	pie_data("Current Top Vulnerability Classes", "class-vulnerabilities.png", $legend, $data);
?>
<!-- END VULNERABILITY CLASSES -->

<!-- BEGIN VULNERABILITIES BY SITE -->
<?
	// Get the sites array
	$vulnerability_sites_array = get_vulnerability_sites_array($key, $selected_site);

        // Create table to hold class information
        echo "<table>\n";
        echo "<tr>\n";
        echo "<td>\n";

	// Print the sites summary
        display_array_results("Current Vulnerabilities by Site", false, $vulnerability_sites_array);

        // Pop the first element off the array
        array_shift($vulnerability_sites_array);

        // Create the trend array
        foreach ($vulnerability_sites_array as $row)
        {
                $site_trends[] = $row[2];
        }

        // Create table to hold trend information
        echo "</td>\n";
        echo "<td>\n";

        // Print the trend summary
        display_trend_summary("Vulnerability Trend Since Last Release", $site_trends);

        // Create table to hold trend information
        echo "</td>\n";
        echo "</tr>\n";
        echo "</table>\n";

        // Create the legend array
        foreach ($vulnerability_sites_array as $row)
        {
                $site_legend[] = $row[0];
        }

        // Create the data array
        foreach ($vulnerability_sites_array as $row)
        {
                $site_data[] = $row[1];
        }

        // Place a pie chart of the current top vulnerability classes
        pie_data("Current Top Vulnerability Sites", "site-vulnerabilities.png", $site_legend, $site_data);
?>
<!-- END VULNERABILITIES BY SITE -->

</BODY>
</HTML>
