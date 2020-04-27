'use strict';

var AV = require('leanengine');
var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var crypto = require('crypto');

AV.init({
  appId: process.env.LEANCLOUD_APP_ID,
  appKey: process.env.LEANCLOUD_APP_KEY,
  masterKey: process.env.LEANCLOUD_APP_MASTER_KEY
});

function parse_sec_host(env_str) {
  let r = /^([\w]+:\/\/[^/]+)/;
  return env_str.split(',').map((v) => {
    let e = r.exec(v.trim());
    return e ? e[1] : null;
  }).filter((v) => {
    return v;
  });
}

let sec_host_str_env = process.env.TTR_SEC_HOST;
let sec_host = sec_host_str_env ? parse_sec_host(sec_host_str_env) : [];
console.log("==== sec host ====");
console.log(sec_host);
// 如果不希望使用 masterKey 权限，可以将下面一行删除
// AV.Cloud.useMasterKey();

var app = express();
app.use(AV.express());

app.use(cookieParser());
// app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({extended: false}));

// 端口一定要从环境变量 `LEANCLOUD_APP_PORT` 中获取。
// LeanEngine 运行时会分配端口并赋值到该变量。
var PORT = parseInt(process.env.LEANCLOUD_APP_PORT);

app.listen(PORT, function (err) {
  console.log('Node app is running on port:', PORT);

  // 注册全局未捕获异常处理器
  // process.on('uncaughtException', function(err) {
  //   console.error('Caught exception:', err.stack);
  // });
  // process.on('unhandledRejection', function(reason, p) {
  //   console.error('Unhandled Rejection at: Promise ', p, ' reason: ', reason.stack);
  // });
});

app.get('/', function (req, res) {
  // var ip = req.headers['x-real-ip']
  // if (!ip) {
  //   ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  //   console.log("Can not get IP by x-real-ip, use: " + ip)
  // }
  res.send("Hello, World!");
});

app.get('/ip', function (req, res) {
  // console.log(req.headers['x-real-ip']);
  // console.log(req.headers['x-forwarded-for']);
  // console.log(req.connection.remoteAddress);
  var ip = req.headers['x-real-ip'];
  if (!ip) {
    ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    console.log("Can not get IP by x-real-ip, use: " + ip);
  }
  res.json({"json": ip});
});

app.get('/db_init/:appKey', async function (req, res) {
  if (!req.params.appKey || req.params.appKey != process.env.LEANCLOUD_APP_KEY) {
    return res.status(403).end("<h1>Forbidden: invalid key!</h1>");
  }
  let if_ok = false;

  let createDb = async function (clazzName) {
    const Obj = AV.Object.extend(clazzName);
    const obj = new Obj();
    await obj.save().then(async (rr) => {

      if_ok = true;
      console.log(`create ${clazzName} obj id:${rr.id}`);
      await rr.destroy();
      console.log(`delete ${clazzName} obj id:${rr.id}`);
      if_ok = true;
    }).catch((e) => {
      console.log(`create object ${clazzName} failed: ${e}`);
      if_ok = false;
      return Promise.reject(e);
    });
  }
  if_ok = false;
  await createDb("Counter_uv");
  if (!if_ok) {
    return res.status(500).end("<h1>create failed.</h1>");
  }

  if_ok = false;
  await createDb("Counter_pv");
  if (!if_ok) {
    return res.status(500).end("<h1>create failed.</h1>");
  }

  return res.send("<h1> Success! </h1>");
  // TODO init from json file, create pv obj for every page
});

function check_sec_host(host/*, origin */) {
  // all pass if sec_host not set
  if (!sec_host.length)
    return true;
  // let r = new RegExp("^" + protocol + ":\\/\\/" + host + "$", "i");
  for (let i = 0; i < sec_host.length; i++)
    if (sec_host[i] == host)
      return true;
  console.log(`ERROR [${host}] not in sec_host`);
  return false;
}

// now, uv only for ip
// tables:
//   counter_pv: pv count, for every page
//     path: pathname
//     count: pv
//   counter_uv: uv, only for site. count of records is equal the site_uv
//     uv_hash: md5(uv_id)  --- not unique
//     uv_id: cookie OR ip+UA  --- not unique
//     last_time: use updatedAt
//   counter_log: log for every request
//     path:
//     host:
//     protocol:
//     origin_referer:
//     ip:
//     ip_type:
//     user-agent:
app.get('/counter/:callback', function (req, res) {
  // console.dir(req.params); //get router param
  // console.dir(req.query); //get param from '?'

  // if (res.cookies && !res.cookies.ttrid) {
    // res.cookie("ttrid", "hello", {sameSite: "None"});
    // sha1(Math.floor(1099511627776 * Math.random()));
  // }
  // if ;
  var cbname = req.params.callback;
  if (cbname.search(/^TTRCb/i) < 0) {
    console.log("callback[" + req.params.callback + "] Error format!");
    return res.status(400).end("<h1>Bad Request !</h1>");
  }

  // var ip = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  let ip = "";
  let ip_type = "";
  if (req.headers['x-real-ip']) {
    ip = req.headers['x-real-ip'];
    ip_type = "XRI";
  } else if (req.headers['x-forwarded-for']) {
    ip = req.headers['x-forwarded-for'];
    ip_type = "XFF";
  } else if (req.connection.remoteAddress) {
    ip = req.connection.remoteAddress;
    ip_type = "TCP";
  } else {
    console.log("Can not get any IP");
  }

  var referer = req.headers['referer'];
  if (!referer) {
    return res.status(400).end("<h1>Bad Request !</h1>");
  }

  var ua = req.headers['user-agent'];

  // var r = /^(.*):\/\/([^/]*)\/([^?]*)\?.*$/i;
  var long = /^(.*):\/\/([^/]*)(\/.*)$/;
  var short = /^(.*):\/\/([^/]*)$/;
  var r;
  if (long.test(referer)) {
    r = long.exec(referer);
  } else if (short.test(referer)) {
    r = short.exec(referer);
  }
  // do not need trim(.replace(/^\s+|\s+$/gm,''))
  var protocol = r[1];
  var host = r[2];
  var path = r.length > 3 ? r[3].replace(/\/\/+/g, "/") : "/";

  if (!check_sec_host(protocol + "://" + host)) {
    return res.status(403).end("<h1>Where are you from ?</h1>");
  }

  var page_pv = 0;
  var site_pv = 0;
  var site_uv = 0;

  //log
  const LOGobject = AV.Object.extend('Counter_log');
  const clog = new LOGobject();
  clog.set("ip", ip ? ip : "unknown");
  clog.set("ip_type", ip_type ? ip_type : "unknown");
  clog.set("UA", ua ? ua : "unknown");
  clog.set("protocol", protocol);
  clog.set("host", host);
  clog.set("path", path);
  clog.set("referer", referer);
  // clog.set("cookie", ttrid)

  let promise_log = clog.save().then((obj) => {
    console.log(`create log: [${ip}]${obj.id}`);
    return Promise.resolve("create log");
  }).catch((e) => {
    console.log(`create log failed[${ip}][${obj.get("path")}]: ${e}`);
    return Promise.reject(e);
  });

  // get pv
  // TODO init pages in pv, ignore the page noe in counter_pv
  const PVquery = new AV.Query('Counter_pv');
  let promise_pv = PVquery.find().then((objs) => {
    let path_ind = -1;
    objs.forEach((obj, index) => {
      site_pv += obj.get("counter");
      if (obj.get("path") == path) {
        if (path_ind > -1) console.log("ERROR: get dup path[" + path + "]");
        path_ind = index;
        page_pv = obj.get("counter");
        obj.increment("counter", 1);
        console.log(`update pv for objectId[${obj.get("path")}]：${obj.id}`);
      }
    });

    if (path_ind > -1) {
      AV.Object.saveAll(objs);
      return Promise.resolve("update pv");
    } else {
      console.log(`path[${path}] first in.`);
      const PVObject = AV.Object.extend('Counter_pv');
      const pv = new PVObject();
      pv.set("path", path);
      pv.set("counter", 1);
      return pv.save().then((obj) => {
        console.log(`create pv for objectId[${obj.get("path")}]：${obj.id}`);
        return Promise.resolve("create pv");
      }).catch((err) => {
        console.log(`create failed[${obj.get("path")}]: ${err}`);
        return Promise.reject("create pv:" + err);
      });
    }
  });

  var uv_id = `${ip}-${ua}-0`;
  var uv_hash = crypto.createHash('SHA1').update(uv_id).digest('hex');

  // get uv
  const UVquery = new AV.Query('Counter_uv');
  var now_tms = new Date(new Date().toLocaleDateString()).getTime();
  let promise_uv = UVquery.find().then((objs) => {
    let new_flag = true;
    objs.forEach((obj) => {
      // uv already get
      if (obj.updatedAt.getTime() >= now_tms && obj.get("uv_hash") == uv_hash)
        new_flag = false;
    });
    site_uv = objs.length;
    if (new_flag) {
      // new UV
      const UVobject = AV.Object.extend('Counter_uv');
      const pv = new UVobject();
      pv.set("uv_id", uv_id);
      pv.set("uv_hash", uv_hash);
      return pv.save().then((obj) => {
        site_uv += 1;
        console.log(`create UV for objectId[${uv_hash}]：${obj.id}`);
        return Promise.resolve("create UV");
      }, (err) => {
        console.log(`create failed[${uv_hash}]: ${err}`);
        return Promise.reject("create UV");
      });
    }
    console.log(`query UV [${uv_hash}]`);
    return Promise.resolve("query UV");
  }).catch((err) => {
    console.log(`query UV failed[${uv_hash}]: ${err}`);
    return Promise.reject("query UV");
  });

  Promise.all([promise_log, promise_pv, promise_uv]).then((vals) => {
    page_pv += 1;
    site_pv += 1;
    res.type('application/javascript');
    var a = {"site_uv": site_uv, "site_pv": site_pv,"page_pv": page_pv, "version": "0.0.1"};
    return res.send("try{" + cbname + "(" + JSON.stringify(a) + ");}catch(e){}");
  }).catch((e) => {
    console.log(`===== error ${e}========`);
    res.status(500).end("<h1>Server Error!</h1>");
  });
});
