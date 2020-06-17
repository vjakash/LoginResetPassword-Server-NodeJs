const bcrypt = require('bcrypt');

const dotenv = require('dotenv');
dotenv.config();

const mongodb = require('mongodb');
const mongoClient = mongodb.mongoClient;
const dbURL = process.env.dbURL;

const express = require('express');
const app = express();

const cors = require('cors');
app.use(cors());
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "*");
    if (req.method == 'OPTIONS') {
        res.header("Access-Control-Allow-Methods", "PUT,POST,GET,DELETE,PATCH");
        return res.status(200).json({});
    }
    next();
})

const bodyParser = require('body-parser');
app.use(bodyParser.json());

const port = process.env.PORT || 3000;

const nodemailer = require('nodemailer');

let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
});

let mailOptions = {
    from: process.env.EMAIL,
    to: '',
    subject: 'Sending Email using Node.js',
    html: `<h1>Hi from node</h1><p> Messsage</p>`
};

app.listen(port, () => {
    console.log(`listening on port ${port}`);
})
app.get('/', (req, res) => {
    res.json({
        message: "welcome to the server"
    })
})
app.post('/register', (req, res) => {
    if (req.body.email == undefined || req.body.password == undefined) {
        res.status(400).json({
            message: "Email or password missing"
        })
    } else {
        mongodb.connect(dbURL, (err, client) => {
            if (err) throw err;
            let db = client.db("cloudstack");
            db.collection("users").findOne({ email: req.body.email }, (err, data) => {
                if (err) throw err;
                if (data) {
                    client.close();
                    res.status(400).json({
                        message: "E-mail already registered"
                    })
                } else {
                    let saltRounds = req.body.email.length;
                    if (saltRounds > 12) {
                        saltRounds = 12;
                    }
                    bcrypt.genSalt(saltRounds, function(err, salt) {
                        if (err) throw err;
                        bcrypt.hash(req.body.password, salt, function(err, hash) {
                            if (err) throw err;
                            // Store hash in your password DB.
                            req.body.password = hash;
                            mongodb.connect(dbURL, (err, client) => {
                                if (err) throw err;
                                let db = client.db("cloudstack");
                                db.collection("users").insertOne(req.body, (err, data) => {
                                    if (err) throw err;
                                    // console.log(data);
                                    client.close();
                                    res.status(200).json({
                                        message: "Registration Successfull"
                                    })
                                })
                            })
                        });
                    });
                }
            })
        })
    }
})

app.post("/login", (req, res) => {
    if (req.body.email == undefined || req.body.password == undefined) {
        res.status(400).json({
            message: "E-mail or password missing"
        })
    } else {
        mongodb.connect(dbURL, (err, client) => {
            if (err) throw err;
            let db = client.db("cloudstack");
            db.collection("users").findOne({ email: req.body.email }, (err, data) => {
                if (err) throw err;
                if (data) {
                    // db.collection("users").findOne({email:req.body.email,password:req.body.password},(err,data)=>{
                    //     if(err) throw err;
                    // })
                    bcrypt.compare(req.body.password, data.password, function(err, result) {
                        // result == true
                        if (result) {
                            client.close();
                            res.status(200).json({
                                message: "login successfull"
                            })
                        } else {
                            client.close();
                            res.status(401).json({
                                message: "password incorrect"
                            })
                        }
                    });
                } else {
                    client.close();
                    res.status(400).json({
                        "message": "user not found"
                    })
                }
            })
        })
    }
})

app.post('/findbyemail', (req, res) => {
    if (req.body.email == undefined) {
        res.status(400).json({
            message: "E-mail missing"
        })
    } else {
        mongodb.connect(dbURL, (err, client) => {
            if (err) throw err;
            let db = client.db("cloudstack");
            db.collection("users").findOne({ email: req.body.email }, (err, data) => {
                if (err) throw err;
                client.close();
                if (data) {
                    res.status(200).json(data);
                } else {
                    res.status(400).json({
                        message: `No user found with Email Id- ${req.body.email}`
                    })
                }

            })
        })
    }
})

app.post('/forgot', (req, res) => {
    require('crypto').randomBytes(32, function(ex, buf) {
        var token = buf.toString('hex');
        // console.log(token);
        mongodb.connect(dbURL, (err, client) => {
            if (err) throw err;
            let expiryInHour = 2;
            let db = client.db("cloudstack");
            db.collection("users").update({ email: req.body.email }, { $set: { reset_token: token } }, (err, data) => {
                if (err) throw err;
                mailOptions.to = req.body.email;
                mailOptions.subject = 'Cloud Stack-Password reset '
                mailOptions.html = `<html><body><h1>Reset Password link</h1>
                                    <h3>Click the link below to redirect to password rest page</h3>
                                    <a href='https://cloudstack.netlify.app/resetpassword/${token}/${req.body.email}'>https://cloudstack.netlify.app/resetpassword/${token}/${req.body.email}</a><br>
                                    <p>The link expires in <strong>${expiryInHour} hrs</strong></p></body></html>`
                transporter.sendMail(mailOptions, function(error, info) {
                    if (error) {
                        console.log(error);
                        res.status(500).json({
                            message: "An error occured,Please try again later"
                        })
                    } else {
                        console.log('Email sent: ' + info.response);
                        let timestamp = new Date();
                        let expiry = expiryInHour * 60 * 60 * 1000;
                        res.status(200).json({
                            message: `Verification mail sent to ${req.body.email}`,
                            email: req.body.email,
                            token,
                            timestamp,
                            expiry
                        })
                    }
                });
            })
        })
    });
})

app.post('/resetpassword', (req, res) => {
    mongodb.connect(dbURL, (err, client) => {
        if (err) throw err;
        let db = client.db("cloudstack");
        db.collection("users").findOne({ email: req.body.email, reset_token: req.body.token }, (err, data) => {
            if (err) throw err;
            if (data) {
                let saltRounds = req.body.email.length;
                if (saltRounds > 12) {
                    saltRounds = 12;
                }
                bcrypt.genSalt(saltRounds, function(err, salt) {
                    if (err) throw err;
                    bcrypt.hash(req.body.password, salt, function(err, hash) {
                        if (err) throw err;
                        // Store hash in your password DB.
                        req.body.password = hash;
                        db.collection("users").update({ email: req.body.email, reset_token: req.body.token }, { $set: { password: hash, reset_token: '', reset_expire: '' } }, (err, data) => {
                            if (err) throw err;
                            // console.log(data);
                            client.close();
                            res.status(200).json({
                                message: "Password Changed successfully"
                            })
                        })
                    });
                });

            } else {
                res.status(400).json({
                    message: "The email id or token is not valid"
                })
            }
        })
    })
})