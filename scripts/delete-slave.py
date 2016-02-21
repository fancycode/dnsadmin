#!/usr/bin/python
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
import optparse
import sys

from dnsadmin import DnsAdminClient

def compare_domains(a, b):
    """Domains will be sorted by name."""
    return cmp(a['domain'], b['domain'])

def main():
    parser = optparse.OptionParser('usage: %prog [options] url')
    parser.add_option('-u', '--username', dest='username',
        help='username to login', metavar='USERNAME')
    parser.add_option('-p', '--password', dest='password',
        help='password to login', metavar='PASSWORD')
    (options, args) = parser.parse_args()
    if not args:
        parser.error('No url given.')
    if not options.username or not options.password:
        parser.error('No username and/or password given.')

    base_url = args[0]
    domains = args[1:]
    if not domains:
        parser.error("No domain given.")

    client = DnsAdminClient(base_url)
    if not client.login(options.username, options.password):
        sys.exit(1)

    for domain in domains:
        deleted = client.unregisterSlave(domain)
        if not deleted:
            print 'Failed to delete "%s"' % (domain)
            continue

        print 'Deleted "%s"' % (deleted)

if __name__ == '__main__':
    main()
