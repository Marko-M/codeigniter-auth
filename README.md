Codeigniter Auth
===================

Codeigniter PHP framework library class for dealing with user authentication.

Instructions
------------

Please note that following steps assume that you have correctly configured Codeigniter on your server.

1. Place auth.php inside application/config.
2. Place Auth.php inside application/libraries.
3. Create your login and register controllers.
4. Adjust application/config/session.php with your `$config['auth_login_controller']`, `$config['auth_session_hash_key']`, `$config['auth_password_hash_key']` and `$config['auth_cookie_hash_key']`.

If your site encounters any kind of security breach you should change some or all of the hash key variables from application/config/session.php.
