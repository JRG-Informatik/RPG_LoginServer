const express = require('express');
const app = express();
const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: true }));

const nodemailer = require('nodemailer');

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('falcon.db');

const ENV = require(__dirname+'/config.json');
const __client = require('path').join(__dirname, '../client/');

db.serialize(()=>{

db.run("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, username TEXT, hash TEXT, verified INTEGER DEFAULT 0)");
db.run("CREATE TABLE IF NOT EXISTS session(userId INTEGER, token TEXT, created_at DATE DEFAULT CURRENT_TIMESTAMP)");
db.run("CREATE TABLE IF NOT EXISTS register(userId INTEGER, token TEXT, created_at DATE DEFAULT CURRENT_TIMESTAMP)");
db.run("CREATE TABLE IF NOT EXISTS reset(userId INTEGER, token TEXT, created_at DATE DEFAULT CURRENT_TIMESTAMP)");

setInterval(()=>{
    db.run("DELETE FROM session WHERE datetime(created_at) < datetime('now', '-6 Hour')");
    db.run("DELETE FROM register WHERE datetime(created_at) < datetime('now', '-24 Hour')");
    db.run("DELETE FROM reset WHERE datetime(created_at) < datetime('now', '-24 Hour')");
} ,1000*60*60);

app.post(ENV.PAGE.LOGIN, async (req, res) => {
    db.get(`SELECT hash, verified, id FROM users WHERE email=?`, [req.body.email], async (err, row)=>{
        if(row && await bcrypt.compare(req.body.password, row.hash)){
            if(!row.verified) return res.send('please verify your email');
            let token = await new Promise((resolve, reject)=>{
                db.get("SELECT token FROM session WHERE userId=?", [row.id], (err, data)=>{resolve(data);});
            });
            if(!token){
                token = {token: crypto.randomBytes(16).toString('hex')};
                db.run(`INSERT INTO session (userId, token) VALUES (?, ?)`,[row.id, token.token]);
            }
        return res.send(token.token);
        }
        res.send('error: invalid login data');
    });
});

app.post(ENV.PAGE.REGISTER, async (req, res) => {
    if(await new Promise((resolve, reject)=>{
        db.get(`SELECT username, email FROM users WHERE username=? OR email=?`, [req.body.username, req.body.email], (err, row)=>{
            resolve(row);
        });
    })) return res.send('error: account already exists');
    let hash = await bcrypt.hash(req.body.password, await bcrypt.genSalt());
    db.run(`INSERT INTO users (email, username, hash) VALUES (?, ?, ?)`, [req.body.email, req.body.username, hash]);
    
    let user = await new Promise((resolve, reject)=>{
        db.get(`SELECT username, email, id FROM users WHERE email=?`, [req.body.email], (err, row)=>{resolve(row);});
    });
    let token = crypto.randomBytes(16).toString('hex');
    db.run(`INSERT INTO register (userId, token) VALUES (?, ?)`, [user.id ,token]);
    let mailOptions = {
        from: ENV.EMAIL.noreply,
        to: user.email,
        subject: 'FALCON | Account validation',
        text: `Hello ${user.username},\n\nTo verify your Falcon account please follow the link: ${ENV.DOMAIN}${ENV.PAGE.CONFIRM_EMAIL}/${token}`
    }
    getMailTransporter().sendMail(mailOptions, (err)=>{if(err){console.log(err);}});
    res.redirect(ENV.PAGE.LOGIN);
});

app.post(ENV.PAGE.REQUEST_RESET_PASSWORD, async (req, res) => {
    let user = await new Promise((resolve, reject)=>{
        db.get("SELECT username, email, id FROM users WHERE email=?", [req.body.email], (err, data)=>{resolve(data);});
    });
    if(!user) return res.redirect(ENV.PAGE.LOGIN);
    db.run("DELETE FROM reset WHERE userId=?", [user.id]);
    let token = crypto.randomBytes(16).toString('hex');
    db.run(`INSERT INTO reset (userId, token) VALUES (?, ?)`, [user.id ,token]);
    let mailOptions = {
        from: ENV.EMAIL.noreply,
        to: user.email,
        subject: 'FALCON | Password Reset',
        text: `Hello ${user.username},\n\nA password reset for your Falcon account was requested.\nTo reset your password follow the link: ${ENV.DOMAIN}${ENV.PAGE.RESET_PASSWORD}/${token}`
    }
    getMailTransporter().sendMail(mailOptions, (err)=>{if(err){console.log(err);}});
});

app.post(ENV.PAGE.RESET_PASSWORD, async(req, res)=>{
    let token = await new Promise((resolve, reject)=>{
        db.get("SELECT userId, token FROM reset WHERE token=?", [req.body.token], (err, data)=>{resolve(data);});
    });
    if(!token) return res.redirect(ENV.PAGE.LOGIN);
    let hash = await bcrypt.hash(req.body.password, await bcrypt.genSalt());
    db.run("UPDATE users SET hash=? WHERE id=?", [hash, token.userId]);
});

const net = require('net');
const client = new net.Socket();
app.post(ENV.PAGE.REQUEST_SERVER_TOKEN, authenticate, async(req, res)=>{
    try{
        let token = crypto.randomBytes(16).toString('hex');

        let transmittedToServer = false;
        client.connect(req.body.port, req.body.ip, ()=>{
            console.log(`Game-Server Token Request [${req.body.ip}:${req.body.port}] [${token}]`);
            let length = Buffer.alloc(8, String.fromCharCode(0x24,0x00,0x00,0x00,0x20,0x00,0x00,0x00));
            let packet = Buffer.concat([length,Buffer.alloc(32, token)]);
            client.write(packet);
        });
        client.on('data', (data)=>{
            console.log(data.subarray(4).toString());
            if(data.subarray(4).toString()==token){
                transmittedToServer = true;
                client.destroy();
            }
        });
        client.on('close', ()=>{
            console.log('closed');
            if(transmittedToServer) res.send(token);
        });
    }catch(e){
        res.send('error: No GameServer found');
    }
    //TODO: send corresponding ip (server) and user session token
});

app.get(ENV.PAGE.LOGIN, async (req, res) => {
    res.sendFile(__client+'login.html');
});

app.get(ENV.PAGE.REGISTER, async (req, res) => {
    res.sendFile(__client+'register.html');
});

app.get(ENV.PAGE.CONFIRM_EMAIL+"/:token", async (req, res) => {
    let entry = await new Promise((resolve, reject)=>{
        db.get("SELECT * FROM register WHERE token=?", [req.params.token], (err, row)=>{
            resolve(row);
            if(row) db.run("DELETE FROM register WHERE token=?", [req.params.token]);
        })
    });
    if(entry) db.run("UPDATE users SET verified=1 WHERE id=?", [entry.userId]);
    res.redirect(ENV.PAGE.LOGIN);
});

app.get(ENV.PAGE.REQUEST_RESET_PASSWORD, async (req, res)=>{
    res.sendFile(__client+'request_reset_password.html');
});

app.get(ENV.PAGE.RESET_PASSWORD+"/:token", async (req, res) => {
    let file = require('fs').readFileSync(__client+'reset_password.html').toString();
    res.send(file.replace('#TOKEN', req.params.token));
});

app.get(ENV.PAGE.HOME, authenticate, async (req, res) => {
    res.send('YEET'+ req.userId);
});

app.listen(80, ()=>{console.log('server running...');});

function authenticate(req, res, next){
    let body = req.method=='POST'?req.body:req.query;
    if(!body || !body.token){
        res.end();
        //res.redirect(ENV.PAGE.LOGIN);
        console.log('failed authentication');
        return;
    }
    db.get(`SELECT userId FROM session WHERE token=?`, [body.token], (err, entry)=>{
        if(entry){
            req.userId = entry.userId;
            next();
        }
        else{
            res.end();
            //res.redirect(ENV.PAGE.LOGIN);
            console.log('failed authentication');
        }
    });
}

function getMailTransporter(){
    return nodemailer.createTransport({
        host:'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
            user: ENV.EMAIL.address,
            pass: ENV.EMAIL.password
        }
    });
}

});