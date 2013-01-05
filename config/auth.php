<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

// Login controller used to redirect
$config['auth_login_controller'] = 'login';

/* Use something complicated. After initial setup change only when you need to
 * force all users to login again (after security breach).
 */
$config['auth_session_hash_key'] = '';

/* Use something complicated. After initial setup change only when you need to
 * force all users to recover their passwords (after security breach).
 */
$config['auth_password_hash_key'] = '';


/* Use something complicated. After initial setup change only when you need to
 * force all remember me option users to login again (after security breach).
 */
$config['auth_cookie_hash_key'] = '';

/* End of file auth.php */
/* Location: ./application/config/auth.php */