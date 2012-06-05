<?
/**
 * WhiteHat Sentinel API Configuration
 */
//define('API_KEY','<INSERT KEY HERE>');

/**
 * Session key encrypting key (32 bytes)
 */
define('ENCRYPTING_KEY', 'ae9b17ead265ac59e0b4b2f65e27fea4');

/**
 * MySQL Database Configuration
 */
define('DB_HOSTNAME', 'localhost');
define('DB_USERNAME', '<USERNAME>');
define('DB_PASSWORD', '<PASSWORD>');
define('DB_DATABASE', '<DATABASE NAME>');

/**
 * Configure Release Dates
 * If true, then use releases database table
 * If false, then just use the first of the month
 */
define('CUSTOM_RELEASE_DATES', 'false');

/**
 * Configure Reporting Period
 * In Number of Months
 */
define('REPORTING_PERIOD', '12');

/**
 * Configure base path
 */
define('BASE_PATH','/var/www/SentinelPlus');

/**
 * Configure Other Directories
 */
define('IMAGE_DIRECTORY', BASE_PATH.'/www/images/');

?>
