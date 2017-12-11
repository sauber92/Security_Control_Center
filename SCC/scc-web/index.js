var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var session = require('express-session');
var fs = require('fs');

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.engine('html', require('ejs').renderFile);

var server = app.listen(3000, function(){
  console.log('Express server has started on port 3000')
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));
app.use('/styles',express.static(__dirname + "/styles"));

var router = require('./router/main')(app, fs);