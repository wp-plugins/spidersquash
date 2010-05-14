<?php
/*
Plugin Name: SpiderSquash
Plugin URI: http://spidersquash.com
Description: SpiderSquash detects and blocks malicious automated access to your web site.  SpiderSquash uses a central blocking database and advanced statistical analysis techniques to detect and block bad bots.  SpiderSquash protects your content and your users from nefarious bot operators.
Version: 0.6
Author: Ersun Warncke
Author URI: http://pivotprogress.com/
*/

/**
 * Copyright (C) 2009  Ersun E. Warncke
 * 
 * Pivot/Progress Sofware Design
 * 2135 Grant St.
 * Eugene, OR 97405
 * 
 * info@spidersquash.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

function squash_init()
{
    if ( squash_admin_warnings() ) {
        
        squash();
    }
    
    add_action('admin_menu', 'squash_config_page');
}

add_action('init', 'squash_init');

if ( ! function_exists('wp_nonce_field') ) {
    
	function squash_nonce_field($action = -1) { return; }
	$squash_nonce = -1;
} 
else {
    
	function squash_nonce_field($action = -1) { return wp_nonce_field($action); }
	$squash_nonce = 'squash-update';
}

function squash_config_page() 
{    
	if ( function_exists('add_submenu_page') )
		add_submenu_page('plugins.php', __('SpiderSquash Configuration'), __('SpiderSquash Configuration'), 'manage_options', 'squash-config', 'squash_conf');
}

function squash_conf()
{
    $messages = array();
    
    $pconnect = function_exists('mysql_pconnect');
    
    if ( isset($_POST['submit']) && $pconnect ) {
        
        if ( function_exists('current_user_can') && ! current_user_can('manage_options') ) 
            die(__('Cheatin&#8217; uh?'));
            
        check_admin_referer( $squash_nonce );
        
        $server = preg_replace( "/[^\w\.]/", "", $_POST['server'] );
        $username = preg_replace( "/[^\w]/", "", $_POST['username'] );
        $password = preg_replace( "/[^\w]/", "", $_POST['password'] );
        
        if ( empty($server) || empty($username) || empty($password) ) {
            
            $squash_status = 'empty';
            $messages[] = 'You must enter a server, username, and password!';
            delete_option('squash_server');
            delete_option('squash_username');
            delete_option('squash_password');
        }
        else {
            
            $squash_status = verify_squash( $server, $username, $password );
        }
        
        if ( $squash_status == 'valid' ) {
            
            update_option( 'squash_server', $server );
            update_option( 'squash_username', $username );
            update_option( 'squash_password', $password );
            $messages[] = 'SpiderSquash account info updated successfully.';
        }
        else {
            
            $messages[] = $squash_status;
        }       
    }
    
    if ( $squash_status != 'valid' && $pconnect ) {
        
        $server = get_option('squash_server');
        $username = get_option('squash_username');
        $password = get_option('squash_password');
        
        $squash_status = verify_squash( $server, $username, $password );
        
        if ( $squash_status != 'valid' ) {
            
            delete_option('squash_server');
            delete_option('squash_username');
            delete_option('squash_password');
            $messages[] = 'Invalid SpiderSquash account info!';
        }
    }
?>
 
<?php if ( ! empty($_POST['submit']) && $pconnect ) : ?>
<div id="message" class="updated fade"><p><strong><?php _e('Options saved.') ?></strong></p></div>
<?php endif; ?>
<div class="wrap">
<h2><?php _e('SpiderSquash Configuration'); ?></h2>
<div class="narrow">
<form action="" method="post" id="squash-conf" style="margin: auto; width: 400px; ">

<?php if ( $pconnect && (! $server || ! $username || ! $password) ) { // BEGIN IF UNSET ?>
	<p><?php printf(__('<a href="%1$s">SpiderSquash</a> blocks malicious automated programs that generate spam, steal content, and hack accounts. If you don\'t have a SpiderSquash account, you can get a free one at <a href="%2$s">SpiderSquash.com</a>.'), 'http://spidersquash.com/', 'http://spidersquash.com/useradd.php'); ?></p>
    
 <?php } // END IF UNSET ?>
    
<?php squash_nonce_field($squash_nonce) ?>

<?php $squash_status == 'valid' ? $message_color = '2d2' : $message_color = 'd22'; ?>

<?php foreach ( $messages as $m ) : ?>
	<p style="padding: .5em; background-color: #<?=$message_color?>; color: #fff; font-weight: bold;"><?=$m?></p>
<?php endforeach; ?>

<?php if ( $pconnect ) { // BEING IF PCONNECT ?>

<h3><label for="server"><?php _e('SpiderSquash Server'); ?></label></h3>
<p><input id="server" name="server" type="text" size="24" value="<?php echo get_option('squash_server'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>

<h3><label for="username"><?php _e('SpiderSquash Username'); ?></label></h3>
<p><input id="username" name="username" type="text" size="8" maxlength="8" value="<?php echo get_option('squash_username'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>

<h3><label for="password"><?php _e('SpiderSquash Password'); ?></label></h3>
<p><input id="password" name="password" type="text" size="32" maxlength="32" value="<?php echo get_option('squash_password'); ?>" style="font-family: 'Courier New', Courier, mono; font-size: 1.5em;" /></p>

<p class="submit"><input type="submit" name="submit" value="<?php _e('Update options &raquo;'); ?>" /></p>

<?php 
} // END IF PCONNECT
else {
?>
    <p style="padding: .5em; background-color: #d22; color: #fff; font-weight: bold;">SpiderSquash requires the mysql_pconnect function which was not found.</p>
<?php
} 
?>
</form>
<?php
}
// END function squash_conf()

function verify_squash($server,$username,$password)
{
    if ( empty($server) || empty($username) || empty($password) ) {
        return 'Incomplete server information.';
    }
        
    if ( mysql_pconnect($server, $username, $password) ) {
        return 'valid';
    }
    else {
        return 'SpiderSquash connection error.  Check account information.';
    }
    
    
} 

function squash_admin_warnings() 
{    
    if ( ! function_exists('mysql_pconnect') ) {
        
        function squash_warning() {
            
            echo "
			<div id='squash-warning' class='updated fade'><p><strong>Error:</strong> SpiderSquash requires the mysql_pconnect function which was not found.</p></div>
			";
        }
        add_action('admin_notices', 'squash_warning');
        return;
    }
       
    if ((! get_option('squash_server') || ! get_option('squash_username') || ! get_option('squash_password')) &&
        !isset($_POST['submit']) ) {
        
        function squash_warning() {
            
            echo "
			<div id='squash-warning' class='updated fade'><p><strong>".__('SpiderSquash is almost ready.')."</strong> ".sprintf(__('You must <a href="%1$s">enter your SpiderSquash account information</a> for it to work.'), "plugins.php?page=squash-config")."</p></div>
			";
        }
        add_action('admin_notices', 'squash_warning');
        return;
    }
    
    return 1;
}

// SpiderSquash Core Functions

function squash()
{
    if ( function_exists('mysql_pconnect') ) {
        
        $s = mysql_pconnect( get_option('squash_server'), get_option('squash_username'), get_option('squash_password') );
    }
    else {
        return;
    }
    
    if ( ! $s ) { return; }
    
    $fnv = fnv($_SERVER['HTTP_USER_AGENT'].$_SERVER['REQUEST_METHOD'].$_SERVER['HTTP_ACCEPT'].$_SERVER['HTTP_ACCEPT_CHARSET'].$_SERVER['HTTP_ACCEPT_ENCODING'].$_SERVER['HTTP_ACCEPT_LANGUAGE'].$_SERVER['HTTP_CONNECTION'].$_SERVER['SERVER_PROTOCOL']);
    
    $r = mysql_query( 'SELECT squashlite.IsBotBeta06('.sprintf( "%u", ip2long($_SERVER['REMOTE_ADDR']) ).','.sprintf( "%u", fnv($_SERVER['HTTP_USER_AGENT']) ).','.sprintf( "%u", $fnv ).',"'.$_SERVER['HTTP_USER_AGENT'].'") AS IsBot' );
    
    
    if ( $row = mysql_fetch_assoc($r) ) {
    	        
    	if ( $row['IsBot'] == 1 ) {

    		header( 'Location: http://redirect.spidersquash.com/?u='.urlencode(myurl()).'&f='.sprintf( "%u", $fnv ) );	
    	}
        elseif ( $row['IsBot'] > 1 ) {

    		header("Location: http://spidersquash.com/squashed.txt");	
    	}
        
    }
}

/* Thanks to http://code.google.com/p/boyanov/wiki/FNVHash for the FNV code */

function fnv($txt)
{
	$buf = str_split($txt);
	$hash = 16777619;
	foreach ($buf as $chr)
	{
		$hash += ($hash << 1) + ($hash << 4) + ($hash << 7) + ($hash << 8) + ($hash << 24);
		$hash = $hash ^ ord($chr);
	}
	$hash = $hash & 0x0ffffffff;
	return $hash;
}

function myurl() {
        
    $url = 'http';
        
    if ($_SERVER["HTTPS"] == "on") {$url .= "s";}
    $url .= "://";
        
    if ($_SERVER["SERVER_PORT"] != "80") {
                
        $url .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];                
    } 
    else {
                
        $url .= $_SERVER["SERVER_NAME"].$_SERVER["REQUEST_URI"];
    }
    return $url;
}
?>