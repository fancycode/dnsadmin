#
# Copyright (C) 2016 Joachim Bauch <mail@joachim-bauch.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import cookielib
import functools
import json
import sys
import urllib2

class parse_response(object):
    """Decorator that parses returned data and checks contents for success."""

    def __init__(self, action):
        self.action = action

    def __call__(self, f):
        @functools.wraps(f)
        def do_parse_response(*args, **kw):
            try:
                data = f(*args, **kw)
            except urllib2.HTTPError, e:
                print >> sys.stderr, '%s failed: %s (%s)' \
                    % (self.action, e.reason, e.code)
                print >> sys.stderr, 'Server response: %s' % (e.read().strip())
                return None

            if data is None:
                return None
            elif not isinstance(data, basestring):
                data = data.read()

            try:
                decoded = json.loads(data)
            except Exception, e:
                print >> sys.stderr, 'Server didn\'t return valid JSON: %s' \
                    % (e)
                print >> sys.stderr, 'Server response: %r' % (data)
                return None

            if not isinstance(decoded, dict):
                print >> sys.stderr, 'Server didn\'t return a map'
                print >> sys.stderr, 'Server response: %r' % (data)
                return None

            if decoded.get('status') != 'ok':
                print >> sys.stderr, 'Server didn\'t return a success status'
                print >> sys.stderr, 'Server response: %r' % (decoded)
                return None

            return decoded['result']

        return do_parse_response

class MethodAwareRequest(urllib2.Request):
    """Request that supports setting a custom HTTP method."""

    def __init__(self, *args, **kw):
        self.method = kw.pop('method', None)
        urllib2.Request.__init__(self, *args, **kw)

    def get_method(self):
        if self.method is not None:
            return self.method

        return urllib2.Request.get_method(self)

class DnsAdminClient(object):
    """Client implementation for the DNS admin service."""

    API_VERSION = 'v1'

    def __init__(self, base_url):
        # Remove any trailing slashes from base url.
        if base_url[-1:] == '/':
            base_url = base_url[:-1]
        self.base_url = base_url + "/api/" + self.API_VERSION
        self.cj = cookielib.CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))

    def _perform_request(self, url, data=None, method=None):
        """Send GET/POST request to the server with correct headers."""
        if data is not None:
            data = json.dumps(data)
            headers = {
                'Content-Type': 'application/json',
            }
            req = MethodAwareRequest(url, data, headers, method=method)
        else:
            req = MethodAwareRequest(url, method=method)
        return self.opener.open(req)

    @parse_response('Login')
    def login(self, username, password):
        """Authenticate user with the service."""
        data = {
            'username': username,
            'password': password,
        }
        return self._perform_request(self.base_url + '/user/login', data)

    @parse_response('Change password')
    def changePassword(self, new_password):
        """Change password of logged in user."""
        data = {
            'password': new_password,
        }
        return self._perform_request(self.base_url + '/user/change-password', data)

    @parse_response('List')
    def listDomains(self):
        """Return list of registered domains."""
        return self._perform_request(self.base_url + '/domain/list')

    @parse_response('Register')
    def registerSlave(self, domain, master):
        """Register slave domain."""
        data = {
            'master': master,
        }
        return self._perform_request(self.base_url + '/slave/' + domain,
            data=data, method='PUT')

    @parse_response('Unregister')
    def unregisterSlave(self, domain):
        """Unregister slave domain."""
        return self._perform_request(self.base_url + '/slave/' + domain,
            method='DELETE')
