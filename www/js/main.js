/*
 * Copyright (C) 2016 Joachim Bauch <mail@joachim-bauch.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
(function() {

require.config({
    waitSeconds: 15,
    paths: {
        "alertify": "libs/alertify-0.3.11.min",
        "angular": "libs/angular-1.5.0.min",
        "angular-route": "libs/angular-route-1.5.0.min",
        "bootstrap": "libs/bootstrap-3.3.6.min",
        "jquery": "libs/jquery-1.12.0.min",
    },
    shim: {
        "angular": {
            "exports": "angular"
        },
        "angular-route": {
            "deps": [
                "angular"
            ]
        },
        "bootstrap": {
            "deps": [
                "jquery"
            ]
        }
    }
});

require([
    "angular",
    "app",
    "angular-route",
    "bootstrap",
], function(angular, app) {

    var module = angular.module('dnsadmin', ['ngRoute']);

    app.initialize(module);

    angular.element(document).ready(function() {
        angular.bootstrap(document, ['dnsadmin']);
    });

});

}());
