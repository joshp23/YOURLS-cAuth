<?php
/*
Plugin Name: cAuth
Plugin URI: https://github.com/joshp23/YOURLS-cAuth
Description: Enables X.509 client side SSL certificate authentication
Version: 0.4.0
Author: Josh Panter
Author URI: https://unfettered.net
*/
// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
/*
 *
 * ADMIN PAGE FUNCTIONS
 *
 *
*/
// Register admin forms
yourls_add_action( 'plugins_loaded', 'cAuth_add_pages' );
function cAuth_add_pages() {
        yourls_register_plugin_page( 'cAuth', 'cAuth', 'cAuth_do_page' );
}
// maybe insert some JS and CSS files to head
yourls_add_action( 'html_head', 'cAuth_head' );
function cAuth_head($context) {
	if ( $context[0] == 'plugin_page_cAuth' ) {
		echo "<link rel=\"stylesheet\" href=\"".YOURLS_SITE."/css/infos.css?v=".YOURLS_VERSION."\" type=\"text/css\" media=\"screen\" />\n";
		echo "<script src=\"".YOURLS_SITE."/js/infos.js?v=".YOURLS_VERSION."\" type=\"text/javascript\"></script>\n";
	}
}
// admin page
function cAuth_do_page() {

	cAuth_update_op();

	$uname = YOURLS_USER;

	global $ydb;
	$table = 'cAuth';
	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$sql = "SELECT * FROM $table WHERE `uname` = :uname";
		$binds = array('uname' => $uname);
		$cAuth = $ydb->fetchOne($sql, $binds);
	} else {
		$cAuth = $ydb->get_row("SELECT * FROM `$table` WHERE `uname` = `$uname`");
	}

	$state = null;

	// Check for valid certificate
	if (cAuth_is_valid()) {
		// get cert hash
		$cs =  cAuth_certID();

		// are we registering a certificate?
		cAuth_registry($uname, $cs);

		$ci = $_SERVER['SSL_CLIENT_I_DN_CN'];
		$cn = $_SERVER['SSL_CLIENT_S_DN_CN'];
		$ce = $_SERVER['SSL_CLIENT_S_DN_Email'];
		$cz = $_SERVER['SSL_CLIENT_V_END'];

		if( $cAuth ) {
			$stored = $cAuth['certserial'];
			if($stored == $cs) {
				$status = 'This certificate is currently registered to your account.';
				$msg 	= '<p>Click here to clear this certificate from your account.</p>';
				$name 	= 'Clear';
				$action = 'clear';
			} else {
				$status = 'This certificate does not match the certificate stored for your account.';
				$msg	='<p>Click here to update your account with this certificate.</p>';
				$name 	= 'Update';
				$action = 'register';
			}
		} else {
			$status = 'No certificate is currently associated with your account';
			$msg	='<p>Click here to register this certificate to your account.</p>';
			$name 	= 'Register';
			$action = 'register';
		}
	} else {
		// no client certificate found in sessison
		if( $cAuth ) {
			$status = 'The following certificate is currently registered to your account <code>'.$cAuth['certserial'].'</code>';
			$msg 	= '<p>Click here to clear this certificate from your account.</p>';
			$name 	= 'Clear';
			$action = 'clear';
		} else {
			$status = 'No certificate is currently associated with your account';
			$msg	= '';
			$name 	= 'Register';
			$action = null;
			$state  = 'disabled';
		}
	}

	// Odds and ends
	$nonce = yourls_create_nonce( 'cAuth' );
	$drop_chk = ( yourls_get_option('cAuth_table_drop') == "drop" ? 'checked' : null );	// Drop db on deactivate?

	$authMgrPlus = yourls_is_active_plugin( 'authMgrPlus/plugin.php' );
	if( $authMgrPlus ) {
		$admin = authMgrPlus_have_capability( AuthMgrPlusCapability::ManagePlugins );
	} else {
		global $cAuth_admin;
		if( isset($cAuth_admin) )
			$admin = in_array($uname, $cAuth_admin);
		else 
			$admin = true;
	}

	echo '
		<div id="wrap">
			<div id="tabs">

				<div class="wrap_unfloat">
					<ul id="headers" class="toggle_display stat_tab">
						<li><a href="#stat_tab_cAuth"><h2>Certificate Registration</h2></a></li>';
	// hide from non-admins if admin option is set
	if( $admin )
		echo '			<li><a href="#stat_tab_admin"><h2>Global</h2></a></li>
						<li><a href="#stat_tab_config"><h2>Config</h2></a></li>';
	// resume normal page draw
	echo '				<li><a href="#stat_tab_cAuthInfos"><h2>Info/Examples</h2></a></li>
					</ul>
				</div>

				<div  id="stat_tab_cAuth" class="tab">';
	// Is there a valid certificate in session?
	if (cAuth_is_valid()) {
		// yes
		echo '		<h3>Presenting Certificate:</h3>
					<p>cAuth has detected a certificate installed in your browser with the following attributes:</p>
					<p>Issued by <strong>'.$ci.'</strong> to <strong>'.$cn.'</strong> ( '.$ce.' )</p>
					<p>Expires on '.$cz.'</p>
					<p>Unique Hash: <code>'.$cs.'</code></p>';
	} else {
		// no
		echo '		<h3>Attention!</h3>
					<p><strong>No certificate found in this browser session!</strong></p>
					<p>This plugin requires a properly configured webserver <strong>and</strong> a valid Client Side SSL Certificate to be installed in your browser. Please refer to the README, your favorite search engine, or <a href="https://0eq2.com/Bp" target="_blank">this</a> walk through to learn more.</p>';
	}
	// resume normal page draw
	echo '			<p>Account Status: '.$status.'</p>
					<hr/>
					<form method="post">
						<input type="hidden" name="nonce" value="'.$nonce.'" />
						<input type="hidden" name="cAuth_registry" value="'.$action.'" />
						<p><input type="submit" value="'.$name.'" '.$state.' />'.$msg.'</p>
					</form>
				</div>';
	// hide from non-admins if admin option is set
	if( $admin ) {
		echo '
			<div id="stat_tab_admin" class="tab">';
		if(isset($cAuth_admin)) {
			echo '
				<h3>cAuth Admins</h3>';
			foreach( $cAuth_admin as $admin )
				echo $admin.'</br>';
			echo '<hr>';

		} elseif( $authMgrPlus )
			echo 'Please refer to Auth Manager Plus for a list of admins';

		else
			echo 'No admin accounts set';

		if( isset( $_GET['action'] ) && $_GET['action'] == 'remove' )
			cAuth_clear($_GET['uname']);

		echo'
					<h3>Global Cert List</h3>
					<form method="post">
						<table id="main_table" class="tblSorter" border="1" cellpadding="5" style="border-collapse: collapse">
							<thead>
								<tr>
									<th>User</th>
									<th>Cert Serial</th>
									<th>&nbsp;</th>
								</tr>
							</thead>
							<tbody>';

		// populate table rows with expiry data if there is any
		$table = 'cAuth';
		if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
			$sql = "SELECT * FROM `$table` ORDER BY uname DESC";
			$cAuth_list = $ydb->fetchObjects($sql);
		} else {
			$cAuth_list = $ydb->get_results("SELECT * FROM `$table` ORDER BY uname DESC");
		}
		if($cAuth_list) {
			foreach( $cAuth_list as $certAuth ) {
				$base	= YOURLS_SITE;
				$uname  = $certAuth->uname;
				$cert   = $certAuth->certserial;
				$remove = ''. $_SERVER['PHP_SELF'] .'?page=cAuth&action=remove&uname='. $uname .'';
				// print if there is any data
				echo '			<tr>
									<td>'.$uname.'</td>
									<td>'.$cert.'</td>
									<td><a href="'.$remove.'">Delete <img src="'.$base.'/images/delete.png" title="remove" border=0></a></td>
								</tr>';
					}
				}
		echo '				
							</tbody>
						</table>
					</form>
				</div>
				<div id="stat_tab_config" class="tab">
					<form method="post">
						<h3>Database Mgmt</h3>

						<p>This plugin automatically saves its databse tables when disabled. You can override this here.</p>
						<div class="checkbox">
						  <label>
							<input name="cAuth_table_drop" type="hidden" value="keep" />
							<input name="cAuth_table_drop" type="checkbox" value="drop" '.$drop_chk.' > Drop the cAuth data when disabled?
						  </label>
						</div>
						
						<input type="hidden" name="nonce" value="'.$nonce.'" />
						<p><input type="submit" value="Submit" /></p>
					</form>
				</div>';
		}

	echo '		<div id="stat_tab_cAuthInfos" class="tab">';
	// hide from non-admins if admin option is set
	if( $admin )
		echo '
					<h3>cAuth admin restriction</h3>
					<p>To restrict what users have access to cAuth admin functions like deleting individual user certificates and the entire certificate database table, add the following to <code>/path/to/YOURLS/user/config.php</code>. If this is enabled, only users listed in that array will see this mesage.</p>
<pre>
// Config: cAuth
$cAuth_admin = array(\''.$uname.'\');
</pre>';
	echo '
					<h3>Obtaining Certificates</h3>
					<p><a href="https://unfettered.net/node/1345" target="_blank">Click here</a> for a simple walk through for creating a Certificate Authority and the required client certificates using <a href="https://opsec.eu/src/tinyca/" target="_blank">TinyCA</a> and <a href="https://www.openssl.org/" target="_blank">OpenSSL</a>.<p>
					<p><strong>Note:</strong> Make sure to generate your certificates on a different computer than your server for security reasons.</p>
					<h3>Installing the Client Certificate</h3>
					<p>In <a href ="https://www.mozilla.org/en-US/firefox/new/" target="_blank">Firefox</a>, this is trivial. Go to <code>Preferences</code>&#8594;<code>Privacy and Security</code> and scroll down to the Security section at the bottom of the page. Click on <code>View Certificates</code> and <code>Import</code> your p12 file. Finally, under "When a server requests your personal certificate", tick "Select one automatically".</p>
					<h3>Server config</h3>
					<p>It is advisable to host using SSL/TSL only. <a href="https://unfettered.net/node/1344" target="_blank">Click here</a> for a simple walkthrough for obtaining free trusted SSL certificate from <a href="https://letsencrypt.org/" target="_blank">Letsencrypt</a>.
					<p>After obtaining your certificates and copying your CA to your server, make sure that mod ssl is enabled in Apache with <code>a2enmod ssl</code> and reload with <code>service apache2 reload</code> if needed. At minimum the following options must be in your Virtual Host file for YOURLS in Apache:</p>
<pre>
# GLOBAL SSL SETTINGS
SSLEngine on
SSLVerifyClient optional
SSLVerifyDepth 1
SSLOptions +StdEnvVars

# CLIENT SIDE CERTIFICATE LOCATION
SSLCACertificateFile /path/to/your/CA/example-cacert.pem
</pre>
					<hr>
					<h3>Additional resources</h3>
					<ul>
						<li><a href="http://www.zytrax.com/tech/survival/ssl.html" target="_blank">In depth explanation</a> of SSL/TLS and X509 certificates.</li>
						<li><a href="https://veewee.github.io/blog/authenticating-with-x509-client-certificates/" target="_blank">A walkthrough</a> for generating a Certificate Authority and certificates in a terminal.</li>
						<li><a href="https://cweiske.de/tagebuch/ssl-client-certificates.htm" target="_blank">A good walkthrough</a> for setting up X509 authentication with PHP apps by Christian Weiske.</li>
					</ul>
				</div>
			</div>
		</div>';
}
/*
 *
 * FORM SUBMISSIONS
 *
 *
*/
function cAuth_registry($uname, $cs) {
	if(isset($_POST['cAuth_registry'])) {
		// Check nonce
		yourls_verify_nonce( 'cAuth' );
		$regCert = $_POST['cAuth_registry'];

		switch($regCert) {
			case 'register':
				global $ydb;
				$table = 'cAuth';
				if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
					$binds = array(	'uname' => YOURLS_USER,
									'certserial' => $cs );
					$sql = "REPLACE INTO $table (uname, certserial) VALUES (:uname, :certserial)";
					$insert = $ydb->fetchAffected($sql, $binds);
				} else {
					$insert = $ydb->query("REPLACE INTO `$table` (uname, certserial) VALUES ('$uname', '$certserial')");
				}
				break;
			case 'clear':
				cAuth_clear(YOURLS_USER);
				break;
			default:
				print 'no action taken';

		}
	}
}
function cAuth_update_op() {
	if(isset( $_POST['cAuth_table_drop'])) {
		// Check nonce
		yourls_verify_nonce( 'cAuth' );
		// Set options
		yourls_update_option( 'cAuth_table_drop', $_POST['cAuth_table_drop'] );
	}
}
/*
 *
 * AUTH MAGIC
 *
 *
*/
yourls_add_filter( 'is_valid_user', 'is_cAuth_user' ); 	// interrupt normal auth process
function is_cAuth_user($valid) {
	// check for correct context
	if ( !yourls_is_API()  && !$valid ) {
		// check for valid certificate
		$cert = cAuth_is_valid();
		if ($cert) {
			// encode cert data
			$certHash = cAuth_certID();
			// check DB for a match
			global $ydb;
			$table = 'cAuth';
			// regardless of YOURLS version (future-proof!)
			if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
				$sql = "SELECT * FROM $table WHERE `certserial` = :certserial";
				$binds = array('certserial' => $certHash);
				$cAuth = $ydb->fetchOne($sql, $binds);
			} else {
				$cAuth = $ydb->get_row("SELECT * FROM `$table` WHERE `certserial` = `$certHash`");
			}
			// if there's a cert match...
			if( $cAuth ) {
				// check user list for a match with DB infos
				global $yourls_user_passwords;
				$uname = $cAuth['uname'];
				foreach( $yourls_user_passwords as $user => $password) {
					if( $uname == $user ) $valid = true;
				}
				if($valid)
					// set auth
					yourls_set_user($uname);
			}
		}
	}
	// return appropriate validation status
	return $valid;
}
/*
 *
 * HELPER FUNCTIONS
 *
 *
*/
// validate certificate
function cAuth_is_valid() {
    if (!isset($_SERVER['SSL_CLIENT_M_SERIAL'])
        || !isset($_SERVER['SSL_CLIENT_V_END'])
        || !isset($_SERVER['SSL_CLIENT_VERIFY'])
        || $_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS'
        || !isset($_SERVER['SSL_CLIENT_I_DN'])
    	) 
        return false;

    if ($_SERVER['SSL_CLIENT_V_REMAIN'] <= 0)
        return false;

    return true;
}
// get certificate hash
function cAuth_certID() {
	if ($_SERVER["SSL_CLIENT_M_SERIAL"]) {
		return sha1($_SERVER["SSL_CLIENT_M_SERIAL"] .
			$_SERVER["SSL_CLIENT_V_START"] .
			$_SERVER["SSL_CLIENT_V_END"] .
			$_SERVER["SSL_CLIENT_S_DN"]);
	}
	return "";
}
/*
 *
 *	Database
 *
 *
*/
// Create tables for this plugin when activated
yourls_add_action( 'activated_cAuth/plugin.php', 'cAuth_activated' );
function cAuth_activated() {
	$init = yourls_get_option('cAuth_init');
	if ($init === false) {
		global $ydb;
		// Create the init value
		yourls_add_option('cAuth_init', time());
		// Create the cAuth table
		$table_cAuth  = "CREATE TABLE IF NOT EXISTS cAuth (";
		$table_cAuth .= "uname varchar(200) NOT NULL, ";
		$table_cAuth .= "certserial char(40) NOT NULL, ";
		$table_cAuth .= "PRIMARY KEY (uname) ";
		$table_cAuth .= ") ENGINE=MyISAM DEFAULT CHARSET=latin1;";

		if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
			$tables = $ydb->fetchAffected($table_cAuth);
		} else {
			$tables = $ydb->query($table_cAuth);
		}

		yourls_update_option('cAuth_init', time());
		$init = yourls_get_option('cAuth_init');
		if ($init === false) {
			die("Unable to properly enable CertAuth due an apparent problem with the database.");
		}
	}
}
// Delete table when plugin is deactivated
yourls_add_action('deactivated_cAuth/plugin.php', 'cAuth_deactivate');
function cAuth_deactivate() {
	$drop = yourls_get_option('cAuth_table_drop');
	if ( $drop == 'drop' ) {
		global $ydb;
		$init = yourls_get_option('cAuth_init');
		if ($init !== false) {
			yourls_delete_option('cAuth_init');
			$table = "cAuth";
			if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
				$sql = "DROP TABLE IF EXISTS $table";
				$ydb->fetchAffected($sql);
			} else {
				$ydb->query("DROP TABLE IF EXISTS $table");
			}
		}
	}
}
// delete cAuth data
function cAuth_clear($uname) {
	global $ydb;
	$table = "cAuth";
	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$binds = array(	'uname' => $uname);
		$sql = "DELETE FROM $table WHERE `uname` = :uname";
		$ydb->fetchAffected($sql, $binds);
	} else {
		$ydb->query("DELETE FROM `$table` WHERE `uname` = '$uname';");
	}
}
?>
