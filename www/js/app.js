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
define([
    "jquery",
    "alertify"
], function(
    $,
    alertify
) {

    var ApiService = ["$q", "$http", function($q, $http) {

        var BASE_URL = "/api/v1";

        var handle_success = function(deferred, response) {
            var data = response.data;
            if (!data || data.status !== "ok") {
                deferred.reject(response);
            } else {
                deferred.resolve(data.result);
            }
        };

        var handle_error = function(deferred, error) {
            deferred.reject(error);
        };

        return {
            status: function() {
                var deferred = $q.defer();
                $http.get(BASE_URL + "/status").then(function(response) {
                    deferred.resolve(response);
                }, function(error) {
                    deferred.reject(error);
                });
                return deferred.promise;
            },
            login: function(username, password) {
                var deferred = $q.defer();

                $http.post(BASE_URL + "/user/login", {
                        username: username,
                        password: password
                    }, {
                    headers: {
                        "Content-Type": "application/json"
                    },
                    responseType: "json"
                }).then(function(response) {
                    handle_success(deferred, response);
                }, function(error) {
                    handle_error(deferred, error);
                });
                return deferred.promise;
            },
            logout: function() {
                var deferred = $q.defer();
                $http.get(BASE_URL + "/user/logout").then(function(response) {
                    handle_success(deferred, response);
                }, function(error) {
                    handle_error(deferred, error);
                });
                return deferred.promise;
            },
            getDomains: function() {
                var deferred = $q.defer();

                $http.get(BASE_URL + "/domain/list", {
                    responseType: "json"
                }).then(function(response) {
                    handle_success(deferred, response);
                }, function(error) {
                    handle_error(deferred, error);
                });
                return deferred.promise;
            },
            addSlave: function(domain, master) {
                var deferred = $q.defer();

                $http.put(BASE_URL + "/slave/"+domain, {
                        master: master
                    }, {
                    headers: {
                        "Content-Type": "application/json"
                    },
                    responseType: "json"
                }).then(function(response) {
                    handle_success(deferred, response);
                }, function(error) {
                    handle_error(deferred, error);
                });
                return deferred.promise;
            },
            deleteSlave: function(domain) {
                var deferred = $q.defer();

                $http.delete(BASE_URL + "/slave/"+domain, {
                    responseType: "json"
                }).then(function(response) {
                    handle_success(deferred, response);
                }, function(error) {
                    handle_error(deferred, error);
                });
                return deferred.promise;
            }
        };

    }];

    var AppController = ["$scope", "$timeout", "ApiService", function($scope, $timeout, api) {

        $scope.loading = true;
        $scope.username = null;
        $scope.domains = null;

        $scope.logindata = {};
        $scope.editform = {};

        var copyright = $("#copyright");
        $scope.showCopyright = function($event) {
            $event.preventDefault();
            copyright.modal();
        };

        $scope.initialize = function() {
            $scope.loading = true;
            api.status().then(function(response) {
                $scope.loading = false;
                var username = response.headers("X-dnsadmin-username");
                if (username) {
                    // Already logged in.
                    $scope.username = username;
                    $scope.updateDomains();
                    return;
                }
            }, function(error) {
                $scope.loading = false;
                console.log("Error", error);
            });
        };

        $timeout($scope.initialize);

        var checkLoginExpired = function(error) {
            if (!error || !error.data) {
                return false;
            }

            var msg;
            switch (error.data.error) {
            case "login_expired":
                msg = "Your session expired, please login again.";
                break;
            case "not_logged_in":
                msg = "You are not logged in. Please make sure to enable cookies and login again.";
                break;
            case "login_failed":
                msg = "Login failed, please check username and/or password and try again.";
                break;
            default:
                return false;
            }

            $scope.logout();
            alertify.alert(msg);
            return true;
        };

        $scope.updateDomains = function() {
            api.getDomains().then(function(domains) {
                $scope.domains = domains;
            }, function(error) {
                console.log("Domains error", error);
                if (checkLoginExpired(error)) {
                    return;
                }
                $scope.domains = null;
            });
        };

        $scope.editDomain = function(domain, master) {
            $scope.editform = {
                domain: domain,
                master: master
            };
            var heading = $("#add_heading");
            $("html,body").animate({
                scrollTop: heading.offset().top
            });
        };

        $scope.logout = function() {
            api.logout();
            $scope.logindata = {};
            $scope.username = null;
            $scope.domains = null;
            $scope.editform = {};
        };

        $scope.login = function(username, password) {
            if (!username  || !password) {
                alertify.alert("Please enter username and password.");
                return;
            }

            api.login(username, password).then(function(response) {
                $scope.username = username;
                $scope.updateDomains();
            }, function(error) {
                console.log("Login error", error);
                if (checkLoginExpired(error)) {
                    return;
                }
                var data = error.data;
                var msg;
                if (data && data.error) {
                    msg = "Login failed, please check username and/or password and try again (" + data.error + ").";
                } else {
                    msg = "Login failed, please check username and/or password and try again.";
                }
                alertify.alert(msg);
            });
        };

        $scope.registerDomain = function(domain, master) {
            api.addSlave(domain, master).then(function(response) {
                alertify.success("The domain " + domain + " has been added / modified.");
                $scope.editform = {};
                $scope.updateDomains();
            }, function(error) {
                console.log("Register error", error);
                if (checkLoginExpired(error)) {
                    return;
                }
                var data = error.data;
                var msg;
                if (data && data.error) {
                    msg = "The domain " + domain + " could not be added / modified, please try again later (" + data.error + ").";
                } else {
                    msg = "The domain " + domain + " could not be added / modified, please try again later.";
                }
                alertify.alert(msg);
            });
        };

        $scope.unregisterDomain = function(domain) {
            alertify.confirm("Really delete domain " + domain + "?", function(confirmed) {
                if (!confirmed) {
                    return;
                }

                api.deleteSlave(domain).then(function(response) {
                    alertify.success("The domain " + domain + " has been deleted.");
                    $scope.updateDomains();
                }, function(error) {
                    console.log("Delete error", error);
                    if (checkLoginExpired(error)) {
                        return;
                    }
                    var data = error.data;
                    var msg;
                    if (data && data.error) {
                        msg = "The domain " + domain + " could not be deleted, please try again later (" + data.error + ").";
                    } else {
                        msg = "The domain " + domain + " could not be deleted, please try again later.";
                    }
                    alertify.alert(msg);
                });
            });
        };
    }];

    return {
        initialize: function(module) {
            module.controller('AppController', AppController);
            module.service('ApiService', ApiService);
        }
    };

});
