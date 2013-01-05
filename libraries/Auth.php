<?php

/**
 * Codeigniter PHP framework library class for dealing with user authentication.
 *
 * @package     CodeIgniter
 * @subpackage	Libraries
 * @category	Authentication
 * @author	Marko Martinović <marko@techytalk.info>
 * @link	https://github.com/Marko-M/codeigniter-auth
 */
class Auth {
    // Codeigniter instance
    protected $CI;

    // Configuration options
    protected $config;

    /**
     * Initialize auth by loading neccesary libraries, helpers and config items.
     *
     * @param array $config Override default configuration
     */
    public function __construct($config = array()) {
        $this->CI = &get_instance();

        // Merge $config and config/auth.php $config
        $this->config = array_merge (
            array(
                'auth_login_controller' =>
                    $this->CI->config->item('auth_login_controller'),
                'auth_session_hash_key' =>
                    $this->CI->config->item('auth_session_hash_key'),
                'auth_password_hash_key' =>
                    $this->CI->config->item('auth_password_hash_key'),
                'auth_cookie_hash_key' =>
                    $this->CI->config->item('auth_session_hash_key')
            ),
            $config
        );

        $this->CI->load->library('session');
        $this->CI->load->helper('cookie');
    }

    /**
     * Checks is user logged in by checking session vars and remember_me cookie.
     *
     * @return boolean Is user logged in or not?
     */
    public function is_logged_in() {
        // Is session logged in?
        if($this->CI->session->userdata('id')) {
            // Are session vars genuine?
            if (
                $this->hash_sha256(
                    array(
                        $this->CI->session->userdata('id'),
                        $this->CI->session->userdata('email'),
                        $this->CI->session->userdata('password_hash')
                    ),
                    'session'
                ) == $this->CI->session->userdata('hash')) {

                return true;
            } else {
                // If session vars aren't genuine, delete them
                $this->logout();
            }
        }

        // Is cookie logged in?
        if(($cookie = get_cookie('remember_me'))) {
            // Is cookie valid?
            if($this->check_cookie($cookie)) {
                return true;
            } else {
                // If cookie isn't valid, delete it
                $this->logout();
            }
        }

        return false;
    }

    /**
     * Login user with given credentials, usually received from
     * login form.
     *
     * @param string $email Email from login form
     * @param string $password Password from login form
     * @param boolean $remember Remember me or not?
     * @return boolean Was login successful or not?
     */
    public function login($email, $password, $remember) {
        $this->CI->load->database();

        // Generate password hash
        $password_hash = $this->hash_sha256($password, 'password');

        $query = $this->CI->db->query(
            'SELECT
                user_id
            FROM '.$this->CI->db->dbprefix.'Users
            WHERE user_email = ? AND user_password_hash = ?',
            array(
                $email,
                $password_hash
            )
        );

        // Are given credentials valid?
        if($query->num_rows() > 0) {
            // If credentials are valid
            $row = $query->row();

            $id = $row->user_id;

            // Set session variables
            $this->set_session($id, $email, $password_hash);

            // Remember me?
            if($remember) {
                // If yes then set cookie
                $this->set_cookie($id);
            }

            return true;
        }

        return false;
    }

    /**
     * Register user with given credentials, usually received from
     * register form.
     *
     * @param type $email
     * @param type $password
     * @return boolean Was register successful or not?
     */
    public function register($email, $password) {
        $this->CI->load->database();

        // Generate password hash
        $password_hash = $this->hash_sha256($password, 'password');

        // Inserd credentials into database
        $query = $this->CI->db->query(
            'INSERT INTO '.$this->CI->db->dbprefix.'Users (
                user_email,
                user_password_hash
            ) VALUES (
                ?,
                ?
            ) ON DUPLICATE KEY UPDATE user_id = user_id',
            array (
                $email,
                $password_hash
            )
        );

        // Are credentials alread taken or not?
        if($query && $this->CI->db->affected_rows() == 1){
            // If not taken
            return true;
        }

        // Alread taken
        return false;
    }

    /**
     * Create necessary database tables.
     *
     * @return boolean Was install successful or not?
     */

    public function install() {
        $this->CI->load->database();

        $sql_users =
        'CREATE TABLE IF NOT EXISTS '.$this->CI->db->dbprefix.'Users (
            user_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_email VARCHAR(100) NOT NULL,
            user_password_hash CHAR(64) NOT NULL,
            PRIMARY KEY(user_id),
            UNIQUE KEY(user_email))
            ENGINE=InnoDB DEFAULT CHARACTER SET utf8,
            DEFAULT COLLATE utf8_general_ci;';

        $sql_tokens =
        'CREATE TABLE IF NOT EXISTS '.$this->CI->db->dbprefix.'Tokens (
            token_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            token_user_id INT UNSIGNED NOT NULL,
            token_hash CHAR(64) NOT NULL,
            PRIMARY KEY(token_id),
            FOREIGN KEY(token_user_id)
                REFERENCES '.$this->CI->db->dbprefix.'Users(user_id)
                    ON DELETE CASCADE ON UPDATE CASCADE)
            ENGINE=InnoDB DEFAULT CHARACTER SET utf8,
            DEFAULT COLLATE utf8_general_ci;';

        if($this->CI->db->query($sql_users) &&
                $this->CI->db->query($sql_tokens)) {
            return true;
        }

        return false;
    }

    /**
     * Log user out by clearing session variables and cookie.
     */
    public function logout(){
        $this->CI->session->sess_destroy();

        delete_cookie('remember_me');
    }

    /**
     * Redirect user to login url and save current url in session
     * if required.
     *
     * @param boolean $remember_current_url Remember current url or not?
     */
    public function redirect_login_url($remember_current_url = true) {
        $this->CI->load->helper('url');

        if($remember_current_url) {
            $this->CI->session->set_userdata('current_url', current_url());
        }

        redirect(site_url($this->config['auth_login_controller']));
    }

    /**
     * Redirect back to url visited before being redirected to login url.
     */
    public function redirect_current_url() {
        $this->CI->load->helper('url');

        $current_url = $this->CI->session->userdata('current_url');
        if(!$current_url){
            $current_url = site_url();
        }

        redirect($current_url);
    }

    /**
     * Set session vars for logged in users detection.
     *
     * @param type $id User ID
     * @param type $email User email
     * @param type $password_hash User password hash
     */
    protected function set_session($id, $email, $password_hash){
        /* Generate $email concat $password_hash sha256 hash. This hash will be
         * used by is_user_logged_in() to check are session vars genuine.
         */
        $hash = $this->hash_sha256 (
            array(
                $id,
                $email,
                $password_hash
            ),
            'session'
        );

        $this->CI->session->set_userdata(
            array(
                'id' => $id,
                'email' => $email,
                'password_hash' => $password_hash,
                'hash' => $hash
            )
        );
    }

    /**
     * Set cookie for logged in users detection.
     *
     * @param type $id User ID
     */
    protected function set_cookie($id){
        $this->CI->load->helper('string');

        // Generate token
        $token = random_string('alnum', 64);

        // Generate token hash
        $token_hash = $this->hash_sha256($token, 'cookie');

        // Insert token hash into database
        $this->CI->db->query(
            'INSERT INTO '.$this->CI->db->dbprefix.'Tokens (
                token_user_id,
                token_hash
            ) VALUES (
                ?,
                ?
            )',
            array(
                $id,
                $token_hash
            )
        );

        /* Set remember_me cookie. Save plain token because we to be able to
         * invalidate existing tokens (cookies) by changing cookie hash key. */
        set_cookie(
            array(
                'name'   => 'remember_me',
                'value'  => $id.' '.$token,
                'expire' => 8640000 // 100 days
            )
        );
    }

    /**
     * Check remember_me cookie.
     *
     * @param type $cookie Cookie data from remember_me cookie.
     * @return boolean remember_me cookie valid or not?
     */
    protected function check_cookie($cookie) {
        $cookie_array = explode(' ', $cookie);

        /* $cookie_array is expected to have two elements, user_id and
         * plain token */
        if(empty($cookie_array) || count($cookie_array) < 2)
            return false;

        $this->CI->load->database();

        $query = $this->CI->db->query(
            'SELECT
                user_id,
                user_email,
                user_password_hash
            FROM '.$this->CI->db->dbprefix.'Tokens
            JOIN '.$this->CI->db->dbprefix.'Users
                ON token_user_id = user_id
            WHERE token_user_id = ? AND token_hash = ?',
            array(
                $cookie_array[0],

                /* Use token hash to be able to invalidate existing
                 * tokens (cookies) by changing cookie hash key. */
                $this->hash_sha256($cookie_array[1], 'cookie')
            )
        );

        // Is token valid?
        if($query->num_rows() > 0) {
            $row = $query->row();

            // If valid set session data...
            $this->set_session(
                $row->user_id,
                $row->user_email,
                $row->user_password_hash
            );

            // ... and regenerate token
            $this->set_cookie($row->user_id);

            return true;
        }

        // Token and cookie aren't valid
        return false;
    }

    /**
     * Generate sha256 hash for given data.
     *
     * @param mixed $to_hash Can be string or array of data
     * @param string $mode Hash key to be used. Can be session, password or cookie.
     * @return string 64 characters hash of has_key concat with the given data
     */
    protected function hash_sha256($to_hash, $mode = 'password') {
        if(is_array($to_hash))
            $to_hash = implode('', $to_hash);

        return hash('sha256', $this->config['auth_'.$mode.'_hash_key'].$to_hash);
    }
}