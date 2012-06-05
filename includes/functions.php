<?

// Include required configuration file
require_once('config.php');
require_once('jpgraph/jpgraph.php');
require_once('jpgraph/jpgraph_line.php');
require_once('jpgraph/jpgraph_plotband.php');
require_once('jpgraph/jpgraph_plotline.php');
require_once('jpgraph/jpgraph_pie.php');
require_once('jpgraph/jpgraph_pie3d.php');

/******************************
 * FUNCTION: DATABASE CONNECT *
 *****************************/
function db_open()
{
        // Connect to the database
        try
        {
                $db = new PDO("mysql:dbname=".DB_DATABASE.";host=127.0.0.1",DB_USERNAME,DB_PASSWORD);

		return $db;
        }
        catch (PDOException $e)
        {
		printf("A fatal error has occurred.  Please contact support.");
                //die("Database Connection Failed: " . $e->getMessage());
        }

	return null;
}

/*********************************
 * FUNCTION: DATABASE DISCONNECT *
 ********************************/
function db_close($db)
{
        // Close the DB connection
        $db = null;
}

/*************************
 * FUNCTION: ENCRYPT KEY *
 ************************/
function encrypt($cleartext)
{
	$iv_size = mcrypt_enc_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
	$key = ENCRYPTING_KEY;
	$text = $cleartext;
	$crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $text, MCRYPT_MODE_ECB, $iv);

	return base64_encode($crypttext);
}

/*************************
 * FUNCTION: DECRYPT KEY *
 ************************/
function decrypt($crypttext)
{
	$crypttext = base64_decode($crypttext);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $key = ENCRYPTING_KEY;
        $data = $crypttext;
        $cleartext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_ECB, $iv);

        return $cleartext;
}

/***************************
 * FUNCTION: GET KEY ALIAS *
 **************************/
function get_key_alias($key)
{
	// Hash the key value
	$key_alias = md5($key);

	return $key_alias;
}

/**********************************
 * FUNCTION: GET VULNS TABLE NAME *
 *********************************/
function get_vulns_table_name($key)
{
        // Get the key alias
        $key_alias = get_key_alias($key);

        // Get the name of the vulnerabiity table
        $vulns_table = $key_alias . "_vulns";

        return $vulns_table;
}

/**********************************
 * FUNCTION: GET SITES TABLE NAME *
 *********************************/
function get_sites_table_name($key)
{
        // Get the key alias
        $key_alias = get_key_alias($key);

        // Get the name of the vulnerabiity table
        $sites_table = $key_alias . "_sites";

        return $sites_table;
}

/*************************************
 * FUNCTION: GET RELEASES TABLE NAME *
 ************************************/
function get_releases_table_name($key)
{
        // Get the key alias
        $key_alias = get_key_alias($key);

        // Get the name of the vulnerabiity table
        $releases_table = $key_alias . "_releases";

        return $releases_table;
}

/***************************
 * FUNCTION: CREATE TABLES *
 **************************/
function create_tables($key)
{
	// Open the database connection
	$db = db_open();

        // Create the vulnerability table if it doesn't already exist
	$vulns_table = get_vulns_table_name($key);
        $stmt = $db->prepare("CREATE TABLE IF NOT EXISTS `?` (id INT(10),class VARCHAR(100),status VARCHAR(8),severity INT(2),threat INT(2),score INT(2),found TIMESTAMP,opened TIMESTAMP,closed TIMESTAMP,url VARCHAR(100),href VARCHAR(100),site VARCHAR(100),retest_state VARCHAR(50))");
	$stmt->bindParam(1, $vulns_table);
	$stmt->execute();

	// Create the sites table if it doesn't already exist
	$sites_table = get_sites_table_name($key);
	$stmt = $db->prepare("CREATE TABLE IF NOT EXISTS `?` (siteid INT(10),sitelabel VARCHAR(100),environment VARCHAR(10))");
	$stmt->bindParam(1, $sites_table);
	$stmt->execute();


        // Create the releases table if it doesn't already exist
        $releases_table = get_releases_table_name($key);
        $stmt = $db->prepare("CREATE TABLE IF NOT EXISTS `?` (date date)");
        $stmt->bindParam(1, $releases_table);
        $stmt->execute();

        // Close the database connection
	db_close($db);
}

/*************************
 * FUNCTION: DROP TABLES *
 ************************/
function drop_tables($key)
{
        // Open the database connection
        $db = db_open();

        // Drop the vulnerability table if it exists
        $vulns_table = get_vulns_table_name($key);
        $stmt = $db->prepare("DROP TABLE IF EXISTS `?`");
        $stmt->bindParam(1, $vulns_table);
        $stmt->execute();

        // Drop the sites table if it exists
        $sites_table = get_sites_table_name($key);
        $stmt = $db->prepare("DROP TABLE IF EXISTS `?`");
        $stmt->bindParam(1, $sites_table);
        $stmt->execute();

        // Drop the releases table if it exists
        $releases_table = get_releases_table_name($key);
        $stmt = $db->prepare("DROP TABLE IF EXISTS `?`");
        $stmt->bindParam(1, $releases_table);
        $stmt->execute();

        // Close the database connection
        db_close($db);
}

/************************************
 * FUNCTION: CHECK VALID KEY FORMAT *
 ***********************************/
function valid_key_format($key)
{
	// Match the expected key format
	if (preg_match("/^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$/", $key))
	{
		return true;
	}
	else return false;
}

/*****************************
 * FUNCTION: GET ENVIRONMENT *
 ****************************/
function get_environment($sitelabel)
{
	// If the site label contains "-test"
        if (preg_match("/-test/i", $sitelabel))
        {
		// The environment is Test
        	return "TEST";
        }
	// If the site label contains "-dev"
	else if (preg_match("/-dev/i", $sitelabel))
	{
		// The environment is Development
		return "DEVELOPMENT";
	}
	// Otherwise assume it's Production
        else return "PRODUCTION";
}

/***************************************
 * FUNCTION: GET VULNERABILITY CLASSES *
 **************************************/
function get_classes($key)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity table
        $vulns_table = get_vulns_table_name($key);

        // CREATE THE ARRAY BODY
        // Get the unique list of all classes of vulnerabilities
        $stmt=$db->prepare("SELECT DISTINCT class FROM `?` ORDER BY class");
        $stmt->bindParam(1, $vulns_table);
        $stmt->execute();

        // Store the unique list of all vulnerability classes in the classes array
        $classes = $stmt->fetchAll();

        // Close the database connection
        db_close($db);

	return $classes;
}

/*******************************
 * FUNCTION: GET LIST OF SITES *
 ******************************/
function get_sites($key)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity table
        $sites_table = get_sites_table_name($key);

        // CREATE THE ARRAY BODY
        // Get the unique list of all classes of vulnerabilities
        $stmt=$db->prepare("SELECT * FROM `?` ORDER BY sitelabel");
        $stmt->bindParam(1, $sites_table);
        $stmt->execute();

        // Store the unique list of all vulnerability classes in the classes array
        $sites = $stmt->fetchAll();

        // Close the database connection
        db_close($db);

        return $sites;
}

/**************************
 * FUNCTION: FULL REFRESH *
 *************************/
function refresh_all($key)
{
	// Refresh the vulnerability data
	$refresh_vulns = refresh_vulnerability_data($key);

	// Refresh the site data
	$refresh_sites = refresh_site_data($key);

	// If both refreshes were successful
	if ($refresh_vulns && $refresh_sites)
	{
		// Return true
		return true;
	}
	// Otherwise return false
	else return false;
}

/************************
 * FUNCTION: FULL PURGE *
 ************************/
function purge_all($key)
{
        // Purge the vulnerability data
        $purge_vulns = purge_vulnerability_data($key);

        // Purge the site data
        $purge_sites = purge_site_data($key);

        // If both purges were successful
        if ($purge_vulns && $purge_sites)
        {
                // Return true
                return true;
        }
        // Otherwise return false
        else return false;
}

/*************************************************
 * FUNCTION: REFRESH SENTINEL VULNERABILITY DATA *
 *************************************************/
function refresh_vulnerability_data($key)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity table
	$vulns_table = get_vulns_table_name($key);

	// Clear out data in the current vulnerability table
	purge_vulnerability_data($key);

        // Get new vulnerability data from WhiteHat
        $url = "https://sentinel.whitehatsec.com/api/vuln/?key=" . $key;
        $vulnerabilities = simplexml_load_file($url);

        // For each new vulnerability found
        foreach ($vulnerabilities->vulnerability as $vulnerability)
        {
                $id = $vulnerability['id'];
                $class = $vulnerability['class'];
                $status = $vulnerability['status'];
                $severity = $vulnerability['severity'];
                $threat = $vulnerability['threat'];
                $score = $vulnerability['score'];
                $found = $vulnerability['found'];
                $opened = $vulnerability['opened'];
                $closed = $vulnerability['closed'];
                $url = $vulnerability['url'];
                $href = $vulnerability['href'];
                $site = $vulnerability['site'];
                $retest_state = $vulnerability['retest_state'];

                // Load new vulnerability data into the vulnerability table
		$stmt = $db->prepare("INSERT INTO `?` (id, class, status, severity, threat, score, found, opened, closed, url, href, site, retest_state) VALUES ('$id', '$class', '$status', '$severity', '$threat', '$score', '$found', '$opened', '$closed', '$url', '$href', '$site', '$retest_state')");
		$stmt->bindParam(1, $vulns_table);
		$stmt->execute();
        }

        // Close the database connection
        db_close($db);

	return true;
}


/***********************************************
 * FUNCTION: PURGE SENTINEL VULNERABILITY DATA *
 ***********************************************/
function purge_vulnerability_data($key)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity table
        $vulns_table = get_vulns_table_name($key);

        // Clear out data in the current vulnerability table
        $stmt = $db->prepare("DELETE FROM `?`");
        $stmt->bindParam(1, $vulns_table);
        $stmt->execute();

        // Close the database connection
        db_close($db);

        return true;
}

/****************************************
 * FUNCTION: REFRESH SENTINEL SITE DATA *
 ****************************************/
function refresh_site_data($key)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the sites table
        $sites_table = get_sites_table_name($key);

        // Clear out data in the current sites table
	purge_site_data($key);

        // Get new site list from WhiteHat
        $url = "https://sentinel.whitehatsec.com/api/site/?key=" . $key;
        $sites = simplexml_load_file($url);

        // For each new site found
        foreach ($sites->site as $site)
        {
                $siteid = $site['id'];
		$sitelabel = $site->label;

		// Get the environment
		$environment = get_environment($sitelabel);

                // Load new site data into the site table
		$stmt = $db->prepare("INSERT INTO `?` (siteid, sitelabel, environment) VALUES ('$siteid', '$sitelabel', '$environment')");
		$stmt->bindParam(1, $sites_table);
		$stmt->execute();
        }

        // Close the database connection
        db_close($db);

	return true;
}

/**************************************
 * FUNCTION: PURGE SENTINEL SITE DATA *
 **************************************/
function purge_site_data($key)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the sites table
        $sites_table = get_sites_table_name($key);

        // Clear out data in the current sites table
        $stmt = $db->prepare("DELETE FROM `?`");
        $stmt->bindParam(1, $sites_table);
        $stmt->execute();

        // Close the database connection
        db_close($db);

        return true;
}

/**************************************
 * FUNCTION: CREATE LIST OF URLS WITH *
 *           VULNERABILITIES          *
 **************************************/
function list_vulnerable_urls($key, $site, $class)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerability and sites tables
        $vulns_table = get_vulns_table_name($key);
	$sites_table = get_sites_table_name($key);

	// If the site is ALL SITES
	if ($site == "ALL SITES")
	{
		// If the class is ALL CLASSES
		if ($class == "ALL CLASSES")
		{
			// Get the list of vulnerability URLs and IDs
			$stmt = $db->prepare("SELECT url,id FROM `?` WHERE status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
			$stmt->execute();
		}
		// The class is something specific
		else
		{
			// Get the list of vulnerability URLs and IDs
			$stmt = $db->prepare("SELECT url,id FROM `?` WHERE class= ? AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $class);
			$stmt->execute();
		}
	}
	// If the site is PRODUCTION
	else if ($site == "PRODUCTION")
        {
                // If the class is ALL CLASSES
                if ($class == "ALL CLASSES")
                {
                        // Get the list of vulnerability URLs and IDs
                        $stmt = $db->prepare("SELECT url,id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $sites_table);
                        $stmt->execute();
                }
                // The class is something specific
                else
                {
                        // Get the list of vulnerability URLs and IDs
                        $stmt = $db->prepare("SELECT url,id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE class= ? AND environment = 'PRODUCTION' AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $class);
                        $stmt->execute();
                }
        }
	// If the site is TEST
	else if ($site == "TEST")
        {
                // If the class is ALL CLASSES
                if ($class == "ALL CLASSES")
                {
                        // Get the list of vulnerability URLs and IDs
                        $stmt = $db->prepare("SELECT url,id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $sites_table);
                        $stmt->execute();
                }
                // The class is something specific
                else
                {
                        // Get the list of vulnerability URLs and IDs
                        $stmt = $db->prepare("SELECT url,id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE class= ? AND environment = 'TEST' AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $class);
                        $stmt->execute();
                }
        }
	// The site is something specific
	else
	{
		// If the class is ALL CLASSES
                if ($class == "ALL CLASSES")
                {
                        // Get the list of vulnerability URLs and IDs
			$stmt = $db->prepare("SELECT url,id FROM `?` WHERE site = ? AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $site);
                        $stmt->execute();
                }
                // The class is something specific
                else
                {
                        // Get the list of vulnerability URLs and IDs
			$stmt = $db->prepare("SELECT url,id FROM `?` WHERE class= ? AND site = ? AND status = 'open' ORDER BY url");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $class);
                        $stmt->bindParam(3, $site);
			$stmt->execute();
                }
	}

	// Print the results
	while ($row = $stmt->fetch())
	{
		echo "<a href=\"https://sentinel.whitehatsec.com/finding/vuln.html?vuln_id=" . $row['id'] . "\" target=\"newwindow\">" . $row['url'] . "</a><br />\n";
	}

        // Close the database connection
        db_close($db);
}

/****************************************
 * FUNCTION: CREATE SUMMARY TABLE BASED *
 *           ON VULNERABILITY DATA      *
 ****************************************/
function create_summary_table($key, $site, $status)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerability and sites tables
        $vulns_table = get_vulns_table_name($key);
	$sites_table = get_sites_table_name($key);

        // Create the summary array
        $summary = array();

        // Current row of the summary array
        $summary_row = 0;

	// CREATE THE HEADER ROW
        // The first column in the summary array should be the vulnerability class
        $summary[$summary_row][0] = "Class";

	// Get the list of releases for the configured reporting period
	$releases = get_releases($key, REPORTING_PERIOD);

        // Release column counter
        $release_column = 1;

        // For each release date
        foreach($releases as $release)
        {
        	// Put the release date into the summary array
                $summary[$summary_row][$release_column] = $release;

                // Increment the release column
                $release_column++;
        }

        // The last column in the summary array should be the total
        $summary[$summary_row][$release_column] = "TOTAL";
        $summary_row++;

	// CREATE THE ARRAY BODY
	// Get the unique list of all classes of vulnerabilities
	$classes = get_classes($key);

	// For each vulnerability class
	foreach ($classes as $class)
	{
        	// Summary array column counter
        	$summary_column = 1;

        	// Set the current vulnerability class
        	$vulnerability_class = $class['class'];
        	$summary[$summary_row][0] = $vulnerability_class;

        	// Reset previous release date
        	$previous_release_date = "0000-00-00";

        	// For each release date
        	foreach ($releases as $release)
        	{
                	// Need to make the previous release date the first release
                	if ($previous_release_date != "0000-00-00")
                	{
				// If we are looking at all found vulnerabilities
				if ($status == "found")
				{
					// If we're looking for all PRODUCTION sites
					if ($site == "PRODUCTION")
					{
						// Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND class= ? AND found > ? AND found < ?");
        					$stmt->bindParam(1, $vulns_table);
						$stmt->bindParam(2, $sites_table);
						$stmt->bindParam(3, $vulnerability_class);
						$stmt->bindParam(4, $previous_release_date);
						$stmt->bindParam(5, $release);
					}
					// If we're looking for all TEST sites
                                        else if ($site == "TEST")
                                        {
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND class= ? AND found > ? AND found < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $sites_table);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
                                        }
					// If we're looking for a specific site
					else if ($site != "ALL SITES")
					{
                        			// Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT id FROM `?` WHERE site = ? AND class= ? AND found > ? AND found < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $site);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
					}
					// We're looking for all sites
					else
					{
						// Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT id FROM `?` WHERE class= ? AND found > ? AND found < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $vulnerability_class);
                                                $stmt->bindParam(3, $previous_release_date);
                                                $stmt->bindParam(4, $release);
					}
				}
				// If we are looking at all closed vulnerabilities
				if ($status == "closed")
				{
                                        // If we're looking for all PRODUCTION sites
                                        if ($site == "PRODUCTION")
                                        {
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND class= ? AND status = 'closed' AND closed > ? AND closed < ?");
						$stmt->bindParam(1, $vulns_table);
						$stmt->bindParam(2, $sites_table);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
                                        }
                                        // If we're looking for all TEST sites
                                        else if ($site == "TEST")
                                        {
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND class= ? AND status = 'closed' AND closed > ? AND closed < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $sites_table);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
                                        }
                                        // If we're looking for a specific site
					else if ($site != "ALL SITES")
					{
						// Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT id FROM `?` WHERE site = ? AND class= ? AND status = 'closed' AND closed > ? AND closed < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $site);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
					}
					// We're looking for all sites
					else
					{
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT id FROM `?` WHERE class= ? AND status = 'closed' AND closed > ? AND closed < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $vulnerability_class);
                                                $stmt->bindParam(3, $previous_release_date);
                                                $stmt->bindParam(4, $release);
					}
				}
				// If we are looking at all open vulnerabilities
				if ($status == "open")
				{
                                        // If we're looking for all PRODUCTION sites
                                        if ($site == "PRODUCTION")
                                        {
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND class= ? AND status = 'open' AND opened > ? AND opened < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $sites_table);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
                                        }
                                        // If we're looking for all TEST sites
                                        else if ($site == "TEST")
                                        {
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND class= ? AND status = 'open' AND opened > ? AND opened < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $sites_table);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
                                        }
                                        // If we're looking for a specific site
                                        else if ($site != "ALL SITES")
                                        {
						// Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT id FROM `?` WHERE site = ? AND class= ? AND status = 'open' AND opened > ? AND opened < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $site);
                                                $stmt->bindParam(3, $vulnerability_class);
                                                $stmt->bindParam(4, $previous_release_date);
                                                $stmt->bindParam(5, $release);
					}
					// We're looking for all sites
					else
					{
                                                // Total number of vulnerabilities for this class and this release date
						$stmt=$db->prepare("SELECT id FROM `?` WHERE class= ? AND status = 'open' AND opened > ? AND opened < ?");
						$stmt->bindParam(1, $vulns_table);
                                                $stmt->bindParam(2, $vulnerability_class);
                                                $stmt->bindParam(3, $previous_release_date);
                                                $stmt->bindParam(4, $release);
					}
				}
				$stmt->execute();
				$result = $stmt->fetchAll();

                        	// Put the vulnerability count into the summary array
                        	$summary[$summary_row][$summary_column] = count($result);

                        	// Increment the summary column marker
                        	$summary_column++;

                        	// Set the current release date to the previous release date for the next iteration
                        	$previous_release_date = $release;
                	}
                	else $previous_release_date = $release;
        	}

        	// Need one last query for any vulnerabilities found after the last release date
                // If we are looking at all found vulnerabilities
                if ($status == "found")
                {
                        // If we're looking for all PRODUCTION sites
                        if ($site == "PRODUCTION")
                        {
                                // Total number of vulnerabilities for this class and this release date
                        	$sql = "SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND class= ? AND found > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $sites_table);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
                        }
                        // If we're looking for all TEST sites
                        else if ($site == "TEST")
                        {
                                // Total number of vulnerabilities for this class and this release date
                        	$sql = "SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND class= ? AND found > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $sites_table);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
                        }
                        // If we're looking for a specific site
			else if ($site != "ALL SITES")
			{
                		// Total number of vulnerabilities for this class and this release date
                        	$sql = "SELECT id FROM `?` WHERE site = ? AND class= ? AND found > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $site);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
			}
			// We're looking for all sites
			else
			{
				// Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT id FROM `?` WHERE class= ? AND found > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $vulnerability_class);
                                $stmt->bindParam(3, $previous_release_date);
			}
                }
                // If we are looking at all closed vulnerabilities
                if ($status == "closed")
                {
                        // If we're looking for all PRODUCTION sites
                        if ($site == "PRODUCTION")
                        {
                                // Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND class= ? AND status = 'closed' AND closed > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $sites_table);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
                                        }
                        // If we're looking for all TEST sites
                        else if ($site == "TEST")
                        {
                                // Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND class= ? AND status = 'closed' AND closed > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $sites_table);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
                        }
                        // If we're looking for a specific site
                        else if ($site != "ALL SITES")
                        {
                		// Total number of vulnerabilities for this class and this release date
                        	$sql = "SELECT id FROM `?` WHERE site = ? AND class= ? AND status = 'closed' AND closed > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $site);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
			}
			// We're looking for all sites
			else
			{
                                // Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT id FROM `?` WHERE class= ? AND status = 'closed' AND closed > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $vulnerability_class);
                                $stmt->bindParam(3, $previous_release_date);
			}
                }
                // If we are looking at all open vulnerabilities
                if ($status == "open")
                {
                        // If we're looking for all PRODUCTION sites
                        if ($site == "PRODUCTION")
                        {
                                // Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND class= ? AND status = 'open' AND opened > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $sites_table);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
                                        }
                        // If we're looking for all TEST sites
                        else if ($site == "TEST")
                        {
                                // Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT * FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND class= ? AND status = 'open' AND opened > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $sites_table);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
                        }
                        // If we're looking for a specific site
                        else if ($site != "ALL SITES")
                        {
                		// Total number of vulnerabilities for this class and this release date
                        	$sql = "SELECT id FROM `?` WHERE site = ? AND class= ? AND status = 'open' AND opened > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $site);
                                $stmt->bindParam(3, $vulnerability_class);
                                $stmt->bindParam(4, $previous_release_date);
			}
			// We're looking for all sites
			else
			{
                                // Total number of vulnerabilities for this class and this release date
                                $sql = "SELECT id FROM `?` WHERE class= ? AND status = 'open' AND opened > ?";
				$stmt->bindParam(1, $vulns_table);
                                $stmt->bindParam(2, $vulnerability_class);
                                $stmt->bindParam(3, $previous_release_date);
			}
                }
		$stmt->execute();
                $result = $stmt->fetchAll();
        	$summary[$summary_row][$summary_column] = count($result);
        	$summary_column++;

        	// Total number of vulnerabilities for this class
		$class_vulnerability_total = 0;

		// For each column in the array except the last
		for ($i=1; $i < count($summary[0]) - 1; $i++)
		{
			// Add up the vulnerabilities for each release
			$class_vulnerability_total += $summary[$summary_row][$i];

			// Put the total number of vulnerabilities in the last column
			$summary[$summary_row][$summary_column] = $class_vulnerability_total;
		}

        	// Increment to the next found row
        	$summary_row++;
	}

	// CREATE THE LAST ROW OF TOTAL VALUES
	// First column should just say "TOTAL"
	$summary[$summary_row][0] = "TOTAL";

	// For each column in the array
        for($i=1; $i < count($summary[0]); $i++)
        {
                // Set the total to zero
                $total = 0;

                // For each row in the array
                for ($j=1; $j < count($summary); $j++)
                {
                        // Add up the values in each row
                        $total = $total + $summary[$j][$i];
                }

		// Put the total in the summary row
		$summary[$summary_row][$i] = $total;
	}
        // Close the database connection
        db_close($db);

	// Return the summary array
	return $summary;
}

/*********************************
 * FUNCTION: PRINT SUMMARY TABLE *
 *********************************/
function print_summary_table($key, $site, $status)
{
        // Create the array that will form our found vulnerabilities table
        $summary = create_summary_table($key, $site, $status);

        // Number of rows in the array
        $summary_rows = count($summary);

        // Number of columns in the array
        $summary_columns = count($summary[0]);

	echo "<table id=\"rounded-corner\" summary=\"" . ucfirst($status) . " Vulnerabilities\">\n";

        for ($row=0; $row < $summary_rows; $row++)
        {
                // If this is the first row in the table it should be the header
                if ($row == 0)
                {
                        echo "<caption>" . ucfirst($status) . " Vulnerabilities</caption>\n";
                        echo "<thead>\n";
                        echo "<tr>\n";

                        // Print each value for the header column
                        for ($column = 0; $column < $summary_columns; $column++)
                        {
                                echo "<th scope=\"col\" class=\"rounded-left\">" . $summary[$row][$column] . "</th>\n";
                        }

                        echo "</tr>\n";
                        echo "</thead>\n";
                        echo "<tbody>\n";
                }
                // Not the first row in the table so it is either the body or the footer
                else
                {
                        // If this is the last row in the table it should be the footer
                        if ($row == $summary_rows - 1)
                        {
                                echo "</tbody>\n";
                                echo "<tfoot>\n";
                                echo "<tr>\n";

                                // Print each value for the footer columns
                                for ($column = 0; $column < $summary_columns; $column++)
                                {
                                        echo "<td scope=\"col\" class=\"rounded-foot\">" . $summary[$row][$column]  . "</td>";
                                }
                                
                                echo "</tr>\n";
                                echo "</tfoot>\n";
                        }
                        // Otherwise it must be the body
                        else
                        {       
                                // Create the new row in the table
                                echo "<tr>\n";
                                
                                // Print each value for the body columns
                                for ($column = 0; $column < $summary_columns; $column++)
                                {        
					// If the total for this vulnerability class is not zero
					if ($summary[$row][$summary_columns - 1] != 0)
					{
						// Print the row for the vulnerability class
                                        	echo "<td>" . $summary[$row][$column]  . "</td>\n";
					}
                                }
                                
                                // End the new row in the table
                                echo "</tr>\n";
                        }
                }
        }

	echo "</table>\n";

        // Return the summary array
        return $summary;
}

/**************************************
 * FUNCTION: SEARCH LIST OF URLS WITH *
 *           VULNERABILITIES          *
 **************************************/
function search_vulnerable_urls($key, $query)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity table
        $vulns_table = get_vulns_table_name($key);

        // Prepare the statement
        $stmt = $db->prepare("SELECT url,id FROM `?` WHERE url LIKE ? AND status = 'open' ORDER BY url");

	// Adding LIKE parameters for the query string
	$query = "%" . $query . "%";

        // Bind the parameter
	$stmt->bindParam(1, $vulns_table);
        $stmt->bindParam(2, $query);

        // Execute the statement
        $stmt->execute();

        // Print the results
        while ($row = $stmt->fetch())
        {
		echo "<a href=\"https://sentinel.whitehatsec.com/finding/vuln.html?vuln_id=" . $row['id'] . "\" target=\"newwindow\">" . $row['url'] . "</a><br />\n";
        }

        // Close the database connection
        db_close($db);
}

/***************************************
 * FUNCTION: GET LIST OF RELEASE DATES *
 ***************************************/
function get_releases($key, $number_of_months)
{
	// If we are set to use custom release dates
	if (CUSTOM_RELEASE_DATES == "true")
	{
	        // Open the database connection
        	$db = db_open();

		// Get the name of the vulnerabiity table
        	$releases_table = get_releases_table_name($key);

		// If number_of_months is not a number
		if (! is_int($number_of_months))
		{
			// Default to 12 months
			$number_of_months = 12;
		}
        
                // Get the most recent release dates
                $stmt = $db->prepare("SELECT date FROM `?` ORDER BY date DESC LIMIT ?");
		$stmt->bindParam(1, $releases_table);
		$stmt->bindParam(2, $number_of_months);
                $stmt->execute();

		// Add the results to the releases array
		$releases = $stmt->fetchAll(PDO::FETCH_COLUMN, 0);

                // Array will come out in order from newest to oldest, but we want the opposite
                sort($releases);

        	// Close the database connection
        	db_close($db);
	}
	// If we are not set to use custom release dates
	else if (CUSTOM_RELEASE_DATES == "false")
	{
        	// Just use the first of the month
        	$month = date('m');
        	$year = date('y');
        	$i = 0;
        	$releases = array();
        	while ($i < $number_of_months)
        	{
                	$timestamp = mktime(0,0,0,$month,1,$year);
                	$releases[$i] = date('Y', $timestamp)."-".date('m', $timestamp)."-01";
                	$month--;
                	$i++;
        	}

		// Array will come out in order from newest to oldest, but we want the opposite
		sort($releases);
	}

	// Return the releases array
	return $releases;
}

/***********************************
 * FUNCTION: GET LAST RELEASE DATE *
 ***********************************/
function get_last_release($key)
{
	// Get the most recent release date
	$releases = get_releases($key, 1);

	// Return  12 AM on the last release date
	return $releases[0];
}

/**********************************************
 * FUNCTION: GET 12 MONTH VULNERABILITY TREND *
 **********************************************/
function get_vulnerability_trend_array($key, $site)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity and sites tables
        $vulns_table = get_vulns_table_name($key);
	$sites_table = get_sites_table_name($key);

	// Get the releases for the last 12 months
	$releases = get_releases($key, 12);

	// Create the summary array
	$summary = array();

	// Current row of the summary array
	$summary_row = 0;

	// CREATE THE HEADER ROW
	// The first column of the header row is empty
	$summary[$summary_row][0] = "";

	// Release column counter
	$release_column = 1;

	// For each release date
	foreach($releases as $release)
	{
		// Put the release date into the summary array
		$summary[$summary_row][$release_column] = $release;

		// Increment the release column
		$release_column++;
	}

	// Go to the next summary row
	$summary_row++;

	// CREATE THE OPENED ROW
	// The first column of the Opened row is Opened
	$summary[$summary_row][0] = "Opened";

	// For each release date list the vulnerabilities found
        for($i=1; $i < count($summary[0]); $i++)
        {
		// Start date is the first row, current column
		$start_date = $summary[0][$i];

		// End date is the first row, next column
		$end_date = $summary[0][$i + 1];

		// If this is the most recent start date
		if ($end_date == "")
		{
			// Then use an end date of now
			$end_date = date('Y-m-d');
		}

		// If the site is Production
		if ($site == "PRODUCTION")
		{
			// Find all vulnerabilities found between the current release and the next one
			$stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND opened >= ? AND opened < ?");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $sites_table);
			$stmt->bindParam(3, $start_date);
			$stmt->bindParam(4, $end_date);
		}
		// If the site is Test
                else if ($site == "TEST")
                {
                        // Find all vulnerabilities found between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND opened >= ? AND opened < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $start_date);
                        $stmt->bindParam(4, $end_date);
                }
		// If the site is not All Sites (ie. looking for something specific)
                else if ($site != "ALL SITES")
                {
                        // Find all vulnerabilities found between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE site = ? AND opened >= ? AND opened < ?");

			// Bind the parameter
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $site);
			$stmt->bindParam(3, $start_date);
                        $stmt->bindParam(4, $end_date);
                }
		// The site is All Sites
                else
                {
                        // Find all vulnerabilities found between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE opened >= ? AND opened < ?");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $start_date);
                        $stmt->bindParam(3, $end_date);
                }

		// Execute the statement
		$stmt->execute();

		// Count the rows returned
		$count = $stmt->rowCount();

		// Place it in the array
		$summary[$summary_row][$i] = $count;
	}

        // Go to the next summary row
        $summary_row++;

        // CREATE THE CLOSED ROW
        // The first column of the Closed row is Closed
        $summary[$summary_row][0] = "Closed";

        // For each release date list the vulnerabilities closed
        for($i=1; $i < count($summary[0]); $i++)
        {
                // Start date is the first row, current column
                $start_date = $summary[0][$i];

                // End date is the first row, next column
                $end_date = $summary[0][$i + 1];

                // If this is the most recent start date 
                if ($end_date == "") 
                {
                        // Then use an end date of now
                        $end_date = date('Y-m-d');
                }

                // If the site is Production
                if ($site == "PRODUCTION")
                {
                        // Find all vulnerabilities closed between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND closed >= ? AND closed < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $start_date);
                        $stmt->bindParam(4, $end_date);
                }
                // If the site is Test
                else if ($site == "TEST")
                {
                        // Find all vulnerabilities closed between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND closed >= ? AND closed < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $start_date);
                        $stmt->bindParam(4, $end_date);
                }
                // If the site is not All Sites (ie. looking for something specific)
                else if ($site != "ALL SITES")
                {
                        // Find all vulnerabilities closed between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE site = ? AND closed >= ? AND closed < ?");
			$stmt->bindParam(1, $vulns_table);
			$stmt->bindParam(2, $site);
                        $stmt->bindParam(3, $start_date);
                        $stmt->bindParam(4, $end_date);
                }
                // The site is All Sites
                else
                {
                        // Find all vulnerabilities closed between the current release and the next one
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE closed >= ? AND closed < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $start_date);
                        $stmt->bindParam(3, $end_date);
                }

                // Execute the statement
                $stmt->execute();

                // Count the rows returned
                $count = $stmt->rowCount();

                // Place it in the array
                $summary[$summary_row][$i] = $count;
        }


        // Go to the next summary row
        $summary_row++;

	// CREATE THE TOTAL ROW
	// The first column of the Total row is TOTAL
	$summary[$summary_row][0] = "<b>TOTAL</b>";

	// For each release date list the total vulnerabilities
        for($i=1; $i < count($summary[0]); $i++)
        {
                // End date is the first row, next column
                $end_date = $summary[0][$i + 1];

                // If this is the most recent start date 
                if ($end_date == "") 
                {
                        // Then use an end date of now
                        $end_date = date('Y-m-d H:m:s');
                }

                // If the site is Production
                if ($site == "PRODUCTION")
                {
			// Find all vulnerabilities found before the end date
			$stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND opened < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $end_date);
                }
                // If the site is Test
                else if ($site == "TEST")
                {
			// Find all vulnerabilities found before the end date
			$stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND opened < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $end_date);
                }
                // If the site is not All Sites (ie. looking for something specific)
                else if ($site != "ALL SITES")
                {
			// Find all vulnerabilities found before the end date
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE site = ? AND opened < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $site);
                        $stmt->bindParam(3, $end_date);
                }
                // The site is All Sites
                else
                {
			// Find all vulnerabilities found before the end date
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE opened < ?");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $end_date);
                }

		// Execute the statement
                $stmt->execute();

                // Count the rows returned
                $found_count = $stmt->rowCount();

                // If the site is Production
                if ($site == "PRODUCTION")
                {
                        // Find all vulnerabilities closed before the end date
                        $stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND closed < ? AND status = 'closed'");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $end_date);
                }
                // If the site is Test
                else if ($site == "TEST")
                {
                        // Find all vulnerabilities closed before the end date
                        $stmt = $db->prepare("SELECT id FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND closed < ? AND status = 'closed'");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $sites_table);
                        $stmt->bindParam(3, $end_date);
                }
                // If the site is not All Sites (ie. looking for something specific)
                else if ($site != "ALL SITES")
                {
                        // Find all vulnerabilities closed before the end date
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE site = ? AND closed < ? AND status = 'closed'");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $site);
                        $stmt->bindParam(3, $end_date);
                }
                // The site is All Sites
                else
                {
                        // Find all vulnerabilities closed before the end date
                        $stmt = $db->prepare("SELECT id FROM `?` WHERE closed < ? AND status = 'closed'");
			$stmt->bindParam(1, $vulns_table);
                        $stmt->bindParam(2, $end_date);
                }

                // Execute the statement
                $stmt->execute();

                // Count the rows returned
                $closed_count = $stmt->rowCount();

		// Total is found minus closed
		$total = $found_count - $closed_count;
                
                // Place it in the array
                $summary[$summary_row][$i] = "<b>" . $total . "</b>";
        }

        // Go to the next summary row
        $summary_row++;
        
        // CREATE THE TREND ROW
        // The first column of the Total row is TREND
        $summary[$summary_row][0] = "<b>TREND</b>";

        // For each release date list the total vulnerabilities
        for($i=1; $i < count($summary[0]); $i++)
        {
		// Trend is opened minus closed
		$trend = $summary[1][$i] - $summary[2][$i];

		// If the trend is not positive or negative
		if ($trend == 0)
		{
			$summary[$summary_row][$i] = "--";
		}
		// If the trend is positive
		else if ($trend > 0)
		{
			$summary[$summary_row][$i] = "<font color=\"red\"><b>+".$trend."</b></font>";
		}
                // If the trend is negative
                else if ($trend < 0)
                {
                        $summary[$summary_row][$i] = "<font color=\"green\"><b>".$trend."</b></font>";
                }
        }

        // Close the database connection
        db_close($db);

	// Return the summary array
	return $summary;
}


/*********************************************
 * FUNCTION: DISPLAY THE VULNERABILITY TREND *
 *           SUMMARY                         *
 *********************************************/
function display_trend_summary($title, $array)
{
        // Number of columns in the array
        $array_columns = count($array);

        // Display the title
        echo "<table id=\"trend\" summary=\"" . ucfirst($title) . "\">\n";

	// Set the starting total to zero
	$total = 0;

        for ($column=0; $column < $array_columns; $column++)
        {
		// Strip non-integer values from the value
		$value = preg_replace('/[^0-9]/','', $array[$column]);

		// If the string contains a +
		if (strpos($array[$column], "+"))
		{
			// Add the value
			$total = $total + $value;
		}
		else if (strpos($array[$column], "-"))
		{
			// Subtract the value
			$total = $total - $value;
		}
	}

        echo "<caption>" . ucfirst($title) . "</caption>\n";
        echo "<tbody>\n"; 
        echo "<tr>\n";

	// If the final total is positive
	if ($total > 0)
	{
		// Add a positive and make it red
		echo "<td><font color=\"red\"><b>+" . $total . "</b></font></td>\n";
	}
	// If the final total is negative
	else if ($total < 0)
	{
		// Add a negative and make it green
		echo "<td><font color=\"green\"><b>" . $total . "</b></font></td>\n";
	}
	// If the final total is zero
	else
	{
		// Just print --
		echo "<td>--</td>\n";
	}
	
	echo "</tr>\n";
	echo "</tbody>\n";
	echo "</table>\n";
}


/*********************************************
 * FUNCTION: DISPLAY THE RESULTS OF AN ARRAY *
 *           IN A TABLE FORMAT               *
 *********************************************/
function display_array_results($title, $footer, $array)
{
	// Number of rows in the array
	$array_rows = count($array);

	// Number of columns in the array
	$array_columns = count($array[0]);

	// Display the title
	echo "<table id=\"rounded-corner\" summary=\"" . ucfirst($title) . "\">\n";

	for ($row=0; $row < $array_rows; $row++)
	{
		// If this is the first row in the table it should be the header
                if ($row == 0)
                {
                        echo "<caption>" . ucfirst($title) . "</caption>\n";
                        echo "<thead>\n";
                        echo "<tr>\n";

                        // Print each value for the header column
                        for ($column = 0; $column < $array_columns; $column++)
                        {
				// If it is a valid date value
				if (preg_match('`^\d{4}-\d{2}-\d{2}$`', $array[$row][$column]))
				{
					// Set the date
					$date = strtotime($array[$row][$column]);

                                	echo "<th scope=\"col\" class=\"rounded-left\">" . date("Y", $date) . "<br />" . date("M d", $date) . "</th>\n";
				}
				// Not a date value
				else
				{
					 echo "<th scope=\"col\" class=\"rounded-left\">" . $array[$row][$column] . "</th>\n";
				}
                        }

                        echo "</tr>\n";
                        echo "</thead>\n";
                        echo "<tbody>\n";
                }
                // Not the first row in the table so it is either the body or the footer
                else
                {
                        // If this is the last row in the table it should be the footer
                        if (($row == $array_rows - 1) && ($footer == "true"))
                        {
                                echo "</tbody>\n";
                                echo "<tfoot>\n";
                                echo "<tr>\n";

                                // Print each value for the footer columns
                                for ($column = 0; $column < $array_columns; $column++)
                                {
                                        echo "<td scope=\"col\" class=\"rounded-foot\">" . $array[$row][$column]  . "</td>\n";
                                }

                                echo "</tr>\n";
                                echo "</tfoot>\n";
                        }
                        // Otherwise it must be the body
                        else
                        {
                                // Create the new row in the table
                                echo "<tr>\n";

                                // Print each value for the body columns
                                for ($column = 0; $column < $array_columns; $column++)
                                {
                                	// Print each body row
                                        echo "<td>" . $array[$row][$column]  . "</td>\n";
                                }

                                // End the new row in the table
                                echo "</tr>\n";
                        }
                }
        }

        echo "</table>\n";
}

/*******************************************
 * FUNCTION: GET VULNERABILITY SITE COUNTS *
 *******************************************/
function get_vulnerability_sites_array($key, $site)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity and sites tables
        $vulns_table = get_vulns_table_name($key);
        $sites_table = get_sites_table_name($key);

        // Create the summary array
        $summary = array();

        // Current row of the summary array
        $row = 0;

        // CREATE THE HEADER ROW
        // The first column of the header row is the class
        $summary[$row][0] = "Site Name";

        // The second column of the header row is the current number of vulnerabilities
        $summary[$row][1] = "Number of Vulnerabilities";

        // The third column of the header row is the trend since the last release
        $summary[$row][2] = "Trend Since Last Release";

	// GET THE CURRENT OPEN VULNERABILITIES BY SITE
        // If the site is Production
        if ($site == "PRODUCTION")
        {
                // Find all vulnerability classes
                $stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'open' GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
                $stmt->bindParam(2, $sites_table);
        }
        // If the site is Test
        else if ($site == "TEST")
        {
                // Find all vulnerabilities closed before the end date
                $stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'open' GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
                $stmt->bindParam(2, $sites_table);
        }
        // If the site is not All Sites (ie. looking for something specific)
        else if ($site != "ALL SITES")
        {
                // Find all vulnerabilities closed before the end date
                $stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE site = ? AND status = 'open' GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
                $stmt->bindParam(2, $sites_table);
                $stmt->bindParam(3, $site);
        }
        // The site is All Sites
        else
        {
                // Find all vulnerabilities closed before the end date
                $stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE status = 'open' GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
                $stmt->bindParam(2, $sites_table);
        }

        // Execute the statement
        $stmt->execute();

        // While there are rows to fetch
        while ($sites = $stmt->fetch())
        {
                // Increment the row
                $row++;

                // Populate the summary array
                $summary[$row][0] = $sites['sitelabel'];

                // Column 1 is the count of the vulnerabilities per site label
                $summary[$row][1] = $sites[1];
        }

        // GET THE PREVIOUS RELEASES OPEN AND CLOSED VULNERABILITIES BY SITE
        // Get the last release date
        $last_release_date = get_last_release($key);

        // If the site is Production
        if ($site == "PRODUCTION")
        {
                // Find production vulnerability sites opened since last release
                $open_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'open' AND opened >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $sites_table);
                $open_stmt->bindParam(3, $last_release_date);

                // Find production vulnerability sites closed since last release
                $close_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'closed' AND closed >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $sites_table);
                $close_stmt->bindParam(3, $last_release_date);
        }
        // If the site is Test
        else if ($site == "TEST")
        {
                // Find test vulnerability sites opened since last release
                $open_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'open' AND opened >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $sites_table);
                $open_stmt->bindParam(3, $last_release_date);

                // Find test vulnerability sites closed since last release
                $close_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'closed' AND closed >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $sites_table);
                $close_stmt->bindParam(3, $last_release_date);
        }
        // If the site is not All Sites (ie. looking for something specific)
        else if ($site != "ALL SITES")
        {
                // Find site specific vulnerability sites opened since last release
                $open_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE site = ? AND status = 'open' AND opened >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $sites_table);
                $open_stmt->bindParam(3, $site);
                $open_stmt->bindParam(4, $last_release_date);

                // Find site specific vulnerability sites closed since last release
                $close_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE site = ? AND status = 'closed' AND closed >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $sites_table);
                $close_stmt->bindParam(3, $site);
                $close_stmt->bindParam(4, $last_release_date);

        }
        // The site is All Sites
        else
        {
                // Find all vulnerability sites opened since last release
                $open_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE status = 'open' AND opened >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $sites_table);
                $open_stmt->bindParam(3, $last_release_date);

                // Find all vulnerability sites closed since last release
                $close_stmt = $db->prepare("SELECT sitelabel, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE status = 'closed' AND closed >= ? GROUP BY sitelabel ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $sites_table);
                $close_stmt->bindParam(3, $last_release_date);
        }

        // Execute the statements
        $open_stmt->execute();
	$close_stmt->execute();

        // Current row of the summary array
        $row = 0;

        // Fetch all results
        $open_sites = $open_stmt->fetchAll();
	$close_sites = $close_stmt->fetchAll();

        // For each class in the summary array
        for ($i = 1; $i <= count($summary); $i++)
        {
                // For each open site since last release
                for ($j = 0; $j < count($open_sites); $j++)
                {
                        // Check if the vulnerability classes match
                        if ($summary[$i][0] == $open_sites[$j]['sitelabel'])
                        {
				$summary[$i][2] = $open_sites[$j][1];

                                // Break the loop
                                break;
                        }
                }

                // For each closed site since last release
                for ($j = 0; $j < count($close_sites); $j++)
                {
                        // Check if the vulnerability classes match
                        if ($summary[$i][0] == $close_sites[$j]['sitelabel'])
                        {
                                $summary[$i][2] = $summary[$i][2] - $close_sites[$j][1];

                                // Break the loop
                                break;
                        }
                }
        }

        // For each site in the summary array
        for ($i = 1; $i < count($summary); $i++)
        {
                // Get the trend
                $trend = $summary[$i][2];


                // If the trend is empty or zero
                if (($trend == "") || ($trend == "0"))
                {
                        $summary[$i][2] = "--";
                }
                // If the trend is positive
                else if ($trend > 0)
                {
                        $summary[$i][2] = "<font color=\"red\"><b>+" . $trend . "</b></font>";
                }
                // If the trend is negative
                else if ($trend < 0)
                {
                        $summary[$i][2] = "<font color=\"green\"><b>" . $trend . "</b></font>";
                }
        }

        // Close the database connection
        db_close($db);

	// Return the summary array
	return $summary;
}

/********************************************
 * FUNCTION: GET VULNERABILITY CLASS COUNTS *
 ********************************************/
function get_vulnerability_class_array($key, $site)
{
        // Open the database connection
        $db = db_open();

        // Get the name of the vulnerabiity and sites tables
        $vulns_table = get_vulns_table_name($key);
        $sites_table = get_sites_table_name($key);

        // Create the summary array
        $summary = array();

        // Current row of the summary array
        $row = 0;

        // CREATE THE HEADER ROW
        // The first column of the header row is the class
        $summary[$row][0] = "Vulnerability Class";

	// The second column of the header row is the current number of vulnerabilities
	$summary[$row][1] = "Current Vulnerabilities";

	// The third column of the header row is the trend since the last release
	$summary[$row][2] = "Trend Since Last Release";

	// GET THE CURRENT OPEN VULNERABILITIES BY CLASS
	// If the site is Production
	if ($site == "PRODUCTION")
        {
        	// Find all vulnerability classes
		$stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'open' GROUP BY class ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
		$stmt->bindParam(2, $sites_table);
        }
        // If the site is Test
        else if ($site == "TEST")
        {
        	// Find all vulnerabilities closed before the end date
		$stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'open' GROUP BY class ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
                $stmt->bindParam(2, $sites_table);
        }
        // If the site is not All Sites (ie. looking for something specific)
        else if ($site != "ALL SITES")
        {
        	// Find all vulnerabilities closed before the end date
		$stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` WHERE site = ? AND status = 'open' GROUP BY class ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
                $stmt->bindParam(2, $site);
        }
        // The site is All Sites
        else
        {
        	// Find all vulnerabilities closed before the end date
        	$stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` WHERE status = 'open' GROUP BY class ORDER BY COUNT(*) DESC");
		$stmt->bindParam(1, $vulns_table);
	}

        // Execute the statement 
	$stmt->execute();

	// While there are rows to fetch
	while ($class = $stmt->fetch())
	{
		// Increment the row
		$row++;

		// Populate the summary array
		$summary[$row][0] = $class['class'];

		// Column 1 is the count of the class of vulnerabilities
		$summary[$row][1] = $class[1];
	}

	// GET THE PREVIOUS RELEASES OPENED AND CLOSED VULNERABILITIES BY CLASS
	// Get the last release date
	$last_release_date = get_last_release($key);

        // If the site is Production
        if ($site == "PRODUCTION")
        {
                // Find all production vulnerabilities opened since last release
                $open_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'open' AND opened >= ? GROUP BY class ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $sites_table);
                $open_stmt->bindParam(3, $last_release_date);

		// Find all production vulnerabilities closed since last release
                $close_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'PRODUCTION' AND status = 'closed' AND closed >= ? GROUP BY class ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $sites_table);
                $close_stmt->bindParam(3, $last_release_date);
        }
        // If the site is Test
        else if ($site == "TEST")
        {
                // Find all test vulnerabilities opened since last release
                $open_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'open' AND opened >= ? GROUP BY class ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $sites_table);
                $open_stmt->bindParam(3, $last_release_date);

                // Find all test vulnerabilities closed since last release
                $close_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` a INNER JOIN `?` b ON a.site = b.siteid WHERE environment = 'TEST' AND status = 'closed' AND closed >= ? GROUP BY class ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $sites_table);
                $close_stmt->bindParam(3, $last_release_date);
        }
        // If the site is not All Sites (ie. looking for something specific)
        else if ($site != "ALL SITES")
        {
                // Find site specific vulnerabilities opened since last release
                $open_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` WHERE site = ? AND status = 'open' AND opened >= ? GROUP BY class ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $Open_stmt->bindParam(2, $site);
		$open_stmt->bindParam(3, $last_release_date);

                // Find site specific vulnerabilities closed since last release
                $close_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` WHERE site = ? AND status = 'closed' AND closed >= ? GROUP BY class ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $site);
                $close_stmt->bindParam(3, $last_release_date);
        }
        // The site is All Sites
        else
        {
                // Find all vulnerabilities opened since last release
                $open_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` WHERE status = 'open' AND opened >= ? GROUP BY class ORDER BY COUNT(*) DESC");
		$open_stmt->bindParam(1, $vulns_table);
                $open_stmt->bindParam(2, $last_release_date);

                // Find all vulnerabilities closed since last release
                $close_stmt = $db->prepare("SELECT class, COUNT(*) AS num FROM `?` WHERE status = 'closed' AND closed >= ? GROUP BY class ORDER BY COUNT(*) DESC");
                $close_stmt->bindParam(1, $vulns_table);
                $close_stmt->bindParam(2, $last_release_date);
        }

        // Execute the statements
        $open_stmt->execute();
	$close_stmt->execute();

        // Current row of the summary array
        $row = 0;

	// Fetch all results
	$open_classes = $open_stmt->fetchAll();
	$close_classes = $close_stmt->fetchAll();

	// For each class in the summary array
	for ($i = 1; $i <= count($summary); $i++)
	{
		// For each open class since last release
		for ($j = 0; $j < count($open_classes); $j++)
		{
			// Check if the vulnerability classes match
			if ($summary[$i][0] == $open_classes[$j]['class'])
			{
				$summary[$i][2] = $open_classes[$j][1];

				// Break the loop
				break;
			}
		}

		// For each closed class since last release
                for ($j = 0; $j < count($close_classes); $j++)
                {
                        // Check if the vulnerability classes match
                        if ($summary[$i][0] == $close_classes[$j]['class'])
                        {
                                $summary[$i][2] = $summary[$i][2] - $close_classes[$j][1];

                                // Break the loop
                                break;
                        }
                }

	}

        // For each class in the summary array
        for ($i = 1; $i < count($summary); $i++)
        {
                // Get the trend
                $trend = $summary[$i][2];


                // If the trend is empty or zero
                if (($trend == "") || ($trend == "0"))
                {
                        $summary[$i][2] = "--";
                }
                // If the trend is positive
                else if ($trend > 0)
                {
                        $summary[$i][2] = "<font color=\"red\"><b>+" . $trend . "</b></font>";
                }
                // If the trend is negative
                else if ($trend < 0)
                {
                        $summary[$i][2] = "<font color=\"green\"><b>" . $trend . "</b></font>";
                }
        }

        // Close the database connection
        db_close($db);

	// Return the summary array
	return $summary;
}

/************************
 * FUNCTION: GRAPH DATA *
 ************************/
function graph_data($title, $image_name, $x_axis, $data)
{
        // Strip non-integer values from the data
        $data = preg_replace('/[^0-9]/','', $data);
                        
        // Size of the overall graph
        $width = 800;
        $height = 600;

        // Create a graph instance
        $graph = new Graph($width,$height);

        // Specify what scale we want to use,
        // text = text scale for the X-axis
        // int = integer scale for the Y-axis
        $graph->SetScale('textint');

        // Specify X-labels
        $graph->xaxis->SetTickLabels($x_axis);
        $graph->xaxis->SetLabelAngle(90);

        // Set the graph title
        $graph->title->Set($title);

        // Create the linear plot
        $lineplot=new LinePlot($data);

        // Add the plot to the graph
        $graph->Add($lineplot);

        // Set the color for the plot
        $lineplot->SetColor("black");
        $lineplot->SetWeight(2);

        // Display the graph
        $image = IMAGE_DIRECTORY . $image_name;
        $graph->Stroke($image);
        echo "<br /><br /><img src=images/" . $image_name . "?".date("U").">";
}

/************************
 * FUNCTION: GRAPH DATA *
 ************************/ 
function pie_data($title, $image_name, $legends, $data)
{
	// Strip non-integer values from the data
        $data = preg_replace('/[^0-9]/','', $data);

	// Create a new pie chart instance
	$graph = new PieGraph (900,400,"auto");
	$graph->SetShadow();

	// Set the pie chart title
	$graph->title->Set($title);

	// Create the pie plot
	$pieplot = new PiePlot3D($data);

	// Add the legends to the graph
	$pieplot->SetLegends($legends);

	// Set the pieplot size
	$pieplot->SetSize(0.3);

	// Explode the slices
	$pieplot->ExplodeAll();

	// Add the plot to the graph
	$graph->Add($pieplot);

	// Display the chart
	$image = IMAGE_DIRECTORY . $image_name;
	$graph->Stroke($image);
	echo "<br /><br /><img src=images/" . $image_name . "?".date("U").">";
}

?>
