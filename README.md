Codeigniter Auth
===================

Codeigniter PHP framework library class for dealing with user authentication.

Instructions
------------

Please note that following steps assume that you have correctly configured Codeigniter on your server.

1. Place auth.php inside application/config.
2. Place Auth.php inside application/libraries.
3. Create your login and register controllers.
4. Adjust application/config/session.php with your `$config['auth_login_controller']` and `$config['auth_hash_key']`.

Please note that changing `$config['auth_hash_key']` will invalidate all current sessions and user registrations.
