var mysql = require('mysql');
var dbconfig = require('../config/database.js');
var instruction = require('../config/instruction.js');
var connection = mysql.createConnection(dbconfig);
var multer = require('multer');
var storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'firmware/');
  },
  filename: function (req, file, cb) {
    cb(null, 'firmware');
  }
});
var upload = multer({ storage: storage });

module.exports = function(app, fs) {
  app.post('/post',function(req, res) {
    var obj = {
      'id': req.body.id,
      'name': req.body.name,
      'user': req.body.user,
      'device': req.body.device,
      'location': req.body.location,
      'ip': req.body.ip,
      'device_id': req.body.device_id,
      'firmware': req.body.firmware
    };

    connection.query('insert into scc set ?', obj, function (err, results, fields){
      if (err) {
        console.error(err);
        throw err;
      }
      res.redirect(302,'/');
    });

    connection.query('insert into parity (id) values(?)', obj.device_id);
  });

  app.post('/firmware', function(req, res) {
    var firmware_version = req.body.firmware_version;

    connection.query('update firmware set version = ?', firmware_version, function (err, results, files) {
      if (err) {
        console.error(err);
        throw err;
      }
    })
  });

  app.post('/edit/:id', upload.single('firmware_data'), function(req, res) {
    var id = req.params.id;
    var obj = {
      'name': req.body.name,
      'user': req.body.user,
      'device': req.body.device,
      'location': req.body.location,
      'ip': req.body.ip,
      'device_id': req.body.device_id,
      'firmware': req.body.firmware
    };

    var exec = require('child_process').exec, child;

    child = exec(instruction.instruction1, function (err, stdout, stderr) {
      if (err) {
        console.error(err);
        return;
      }

      console.log(stdout);
    });

    child = exec(instruction.instruction2, function (err, stdout, stderr) {
      if (err) {
        console.error(err);
      }

      console.log(stdout);
    });

    connection.query('update scc set ? where id = ?', [obj,id], function (err, results, fields){
      if (err) {
        console.error(err);
        throw err;
      }
      res.redirect(302,'/');
    });
  });

  app.get('/del/:id', function(req, res) {
    var id = req.params.id;

    connection.query('delete from scc where id = ?', id, function (err, results, fields){
      if (err) {
        console.error(err);
        throw err;
      }
      res.redirect(302,'/');
    });
  });

  app.get('/detail/:id',function(req,res) {
    var id = req.params.id;

    var count_secure_key_manage;
    var count_secure_boot;
    var count_secure_fw_update;
    var count_remote_attestation;
    var count_login_monitoring;
    var count_packet_monitoring;

    var secure_key_manage;
    var secure_boot;
    var secure_fw_update;
    var remote_attestation;
    var login_monitoring;
    var packet_monitoring;

    var firmware_version;

    connection.query('select count(*) as count from secure_key_manage ' +
      'left join scc on (scc.device_id = secure_key_manage.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      count_secure_key_manage = JSON.stringify(results[0].count);
    });

    connection.query('select count(*) as count from secure_boot ' +
      'left join scc on (scc.device_id = secure_boot.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      count_secure_boot = JSON.stringify(results[0].count);
    });

    connection.query('select count(*) as count from secure_fw_update ' +
      'left join scc on (scc.device_id = secure_fw_update.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      count_secure_fw_update = JSON.stringify(results[0].count);
    });

    connection.query('select count(*) as count from remote_attestation ' +
      'left join scc on (scc.device_id = remote_attestation.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      count_remote_attestation = JSON.stringify(results[0].count);
    });

    connection.query('select count(*) as count from login_monitoring ' +
      'left join scc on (scc.device_id = login_monitoring.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      count_login_monitoring = JSON.stringify(results[0].count);
    });

    connection.query('select count(*) as count from packet_monitoring ' +
      'left join scc on (scc.device_id = packet_monitoring.id)' +
      'where (scc.id = ?) and (packet_log is not null)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      count_packet_monitoring = JSON.stringify(results[0].count);
    });

    // log + parity + time
    connection.query('select * from secure_key_manage ' +
      'left join scc on (scc.device_id = secure_key_manage.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      secure_key_manage = results;
    });

    connection.query('select * from secure_boot ' +
      'left join scc on (scc.device_id = secure_boot.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      secure_boot = results;
    });

    connection.query('select * from secure_fw_update ' +
      'left join scc on (scc.device_id = secure_fw_update.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      secure_fw_update = results;
    });

    connection.query('select * from remote_attestation ' +
      'left join scc on (scc.device_id = remote_attestation.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      remote_attestation = results;
    });

    connection.query('select * from login_monitoring ' +
      'left join scc on (scc.device_id = login_monitoring.id)' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      login_monitoring = results;
    });

    connection.query('select * from packet_monitoring ' +
      'left join scc on (scc.device_id = packet_monitoring.id)' +
      'where (scc.id = ?) and (packet_log is not null)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      packet_monitoring = results;
    });

    // firmware update
    connection.query('select version from firmware', function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      firmware_version = results;
    });

    // device
    connection.query('select * from scc ' +
      'where (scc.id = ?)', id, function (err, results, fields) {
      if (err) {
        console.error(err);
        throw err;
      }

      res.render('detail', {
        title: 'SCC | Security Control Center',
        h1: 'Security Control Center',
        rows: results,

        count_secure_key_manage: count_secure_key_manage,
        count_secure_boot: count_secure_boot,
        count_secure_fw_update: count_secure_fw_update,
        count_remote_attestation: count_remote_attestation,
        count_login_monitoring: count_login_monitoring,
        count_packet_monitoring: count_packet_monitoring,

        secure_key_manage: secure_key_manage,
        secure_boot: secure_boot,
        secure_fw_update: secure_fw_update,
        remote_attestation: remote_attestation,
        login_monitoring: login_monitoring,
        packet_monitoring: packet_monitoring,

        firmware_version: firmware_version
      });
    });
  });

  app.get('/',function(req, res) {
    var count;
    var err_count = 0;
    var firmware_version;
    var firmware_date;

    connection.query('select distinct id from secure_key_manage', function(err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      for (var i = 0; i < results.length; i++) {
        connection.query('select id, key_parity from secure_key_manage where id = ? ' +
          'order by key_time', results[i].id, function (e, r, f) {
          if (e) {
            console.log(e);
            throw e;
          }

          connection.query('update parity set key_parity = ? where id = ?',
            [r[r.length-1].key_parity, r[r.length-1].id]);
        });
      }
    });

    connection.query('select distinct id from secure_boot', function(err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      for (var i = 0; i < results.length; i++) {
        connection.query('select id, boot_parity from secure_boot where id = ? ' +
          'order by boot_time', results[i].id, function (e, r, f) {
          if (e) {
            console.log(e);
            throw e;
          }

          connection.query('update parity set boot_parity = ? where id = ?',
            [r[r.length-1].boot_parity, r[r.length-1].id]);
        });
      }
    });

    connection.query('select distinct id from secure_fw_update', function(err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      for (var i = 0; i < results.length; i++) {
        connection.query('select id, update_parity from secure_fw_update where id = ? ' +
          'order by update_time', results[i].id, function (e, r, f) {
          if (e) {
            console.log(e);
            throw e;
          }

          connection.query('update parity set update_parity = ? where id = ?',
            [r[r.length-1].update_parity, r[r.length-1].id]);
        });
      }
    });

    connection.query('select distinct id from remote_attestation', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      for (var i = 0; i < results.length; i++) {
        connection.query('select id, attestation_parity from remote_attestation where id = ? ' +
          'order by attestation_time', results[i].id, function (e, r, f) {
          if (e) {
            console.log(e);
            throw e;
          }

          connection.query('update parity set attestation_parity = ? where id = ?',
            [r[r.length-1].attestation_parity, r[r.length-1].id]);
        });
      }
    });

    connection.query('select * from parity', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      for (var i = 0; i < results.length; i++) {
        if (results[i].key_parity === "ERROR" | results[i].boot_parity === "ERROR" |
          results[i].update_parity === "ERROR" | results[i].attestation_parity === "ERROR") {
          connection.query('update scc set parity = "ERROR" where device_id = ?', results[i].id);
        } else {
          connection.query('update scc set parity = "OK" where device_id = ?', results[i].id);
        }
      }
    });

    connection.query('select id from parity where key_parity = "unkown"', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      for (var i = 0; i < results.length; i++) {
        connection.query('update scc set parity = "UNKOWN" where device_id = ?', results[i].id);
      }
    });

    // count
    connection.query('select count(*) as count from scc', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      count = JSON.stringify(results[0].count);
    });

    // err_count
    connection.query('select count(*) as err_count from scc ' +
      'where (parity = "ERROR") or (parity = "UNKOWN")', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      err_count = JSON.stringify(results[0].err_count);
    });

    // firmware_version
    connection.query('select * from firmware', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      firmware_version = JSON.stringify(results[0].version);
      firmware_date = JSON.stringify(results[0].date);
    });

    // scc
    connection.query('select * from scc', function (err, results, fields) {
      if (err) {
        console.log(err);
        throw err;
      }

      res.render('index', {
        title: "SCC | Security Control Center",
        h1: "Security Control Center",
        count: count,
        err_count: err_count,
        firmware_version: firmware_version,
        firmware_date: firmware_date,
        rows: results
      });
    });
  });
};
