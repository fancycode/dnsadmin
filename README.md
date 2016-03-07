# Nameserver admin api

## Create users

Users are stored in a `htpasswd` compatible textfile that uses bcrypt as hash
encryption for passwords.

    $ htpasswd -cBb -C 10 users.conf foo bar


## Endpoints

Data must be sent as `application/json`, all responses are `application/json`.


### GET /status

Check if API service is running.

Request:

- none

Response:

- Returns `ok` if the service is running or an error otherwise.


### POST /user/login

Authenticate user.

Request:

- `username` (username to login, string)
- `password` (password to login with, string)

Response:

- Sets a cookie that must be sent with all further requests.


### GET /user/logout

Remove authentication stored for user.

Request:

- none

Response:

- Expires cookie set by login endpoint.


### POST /user/change-password

Update password for logged in user.

Request:

- `password` (new password, string)

Response:

- Sets a cookie that must be sent with all further requests.


### GET /domain/list

Get list of domains for logged in user.

Request:

- none

Response:

- List of domain entries, each with the fields `domain` (string), `type`
  (string, either `master`or `slave`), `master` (string, ip address of master
  for slaves)


### PUT /slave/{domain}

Register / update a slave domain.

Request:

- `master` (ip address of master for given domain, string)

Response:

- Domain that was registered / updated (string).


### DELETE /slave/{domain}

Unregister a slave domain.

Request:

- none

Response:

- Domain that was unregistered (string).
