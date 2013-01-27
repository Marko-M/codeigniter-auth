Codeigniter Auth
===================
Codeigniter PHP framework library class for dealing with user authentication.

Features
--------
1. Passwords stored as SHA-256 of password + separate hash key = password hash.
2. Current logged in status stored in session as SHA-256 of id + email + password hash + separate hash key = session hash. Ability to validate session by checking session hash on each page load.
3. Remember me cookie is using cookie tokens stored inside database. Remember me cookie is being regenerated on each remember me cookie login.
4. Registration supports both direct and activate token based registration.

Instructions
------------
Please note that following steps assume that you have correctly configured Codeigniter on your server.

1. Place auth.php inside application/config.
2. Place Auth.php inside application/libraries.
3. Create installation controller that calls install() method provided by this library to create all of the required database tables.
4. Create your login and register controllers.
5. Adjust application/config/session.php with your `$config['auth_login_controller']`, `$config['auth_session_hash_key']`, `$config['auth_password_hash_key']`, `$config['auth_cookie_hash_key']` and `$config['auth_activate_hash_key']`.