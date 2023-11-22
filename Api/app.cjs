const express = require('express');
const app = express();
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const moment = require('moment-timezone');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const dotenv = require("dotenv");
dotenv.config();
const AWS = require("aws-sdk");
let multer = require("multer");
const request = require('request');
const https = require('https');
const fs = require('fs');



app.use(bodyParser.json());
app.use(cors({ origin: true }));

//------------ AWS RDS configuration--------------
/* const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
});  */
//--------------end of code----------------------


/* connection.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        process.exit(1);
    }
    console.log('Connected to database');
}); */

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    connectionLimit: process.env.DB_CONNLIMIT,
});


//--------------AWS S3 bucket configuration--------
const bucketName = process.env.BUCKET_NAME;
const awsConfig = {
    accessKeyId: process.env.ACCESS_KEY,
    secretAccessKey: process.env.SECRET_KEY,
    region: process.env.REGION_NAME,
};
const S3 = new AWS.S3(awsConfig);
//----------------end of code----------------------

//----------------MSG91 configyration--------------
const templateId = process.env.TEMPLATE_ID
const authKey = process.env.AUTH_KEY
//----------------end of code-------------------

//------------middleware----------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const storage = multer.memoryStorage();

const { writeFile } = require('fs/promises');
const { loadImage } = require('canvas');



// const port = 8080;
// app.listen(port, () => {
//     console.log(`Server running on port ${port}`);
// });

/* const httpsOptions = {
    key: fs.readFileSync('C:\\Certificates\\private-key.key'), 
    cert: fs.readFileSync('C:\\Certificates\\ca-bundle.crt'),
    
}; */

  const httpsOptions = {
   key: fs.readFileSync('D:\\Skillmuni.in SSL Certificate file\\skillmuni_key.pem'), 
   cert: fs.readFileSync('D:\\Skillmuni.in SSL Certificate file\\skillmuni_certificate.crt'),
   passphrase: 'Tgc@0987'
   
}; 


const server = https.createServer(httpsOptions, app).listen(8080, () => {
   console.log('Server running on https://localhost:8080/');
});   




//-------------api for adding cms users with (emailid,password,organisation,name,usertype)------------------
app.post('/createNewUser', (req, res) => {
    const emailid = req.body.emailid;
    const password = req.body.password;
    const organisation = req.body.organisation;
    const name = req.body.name;
    const usertype = req.body.usertype;
    // const campaign_name = req.body.campaign_name;

    const currentMoment = moment().tz('Asia/Kolkata');
    const date = currentMoment.format('YYYY-MM-DD HH:mm:ss');

    if (usertype === 'superadmin') {

        if (!emailid || !password || !name || !usertype) {
            return res.status(400).json({ message: 'Incomplete details' });
        }
        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Error hashing password: ' + err });
            }
            pool.getConnection((err, connection) => {
                if (err) {
                    console.error("Error getting the connection:", err);
                    return res.status(500).send('Server error');
                }
                const sql = 'INSERT INTO cmsusers(emailid, password, name, usertype, date) VALUES (?,?,?,?,?)';
                connection.query(sql, [emailid, hashedPassword, name, usertype, date], (err, result) => {
                    connection.release();
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Error inserting data: ' + err });
                    }
                    res.status(200).json({ message: 'User created' });
                });
            });
        });
    }


    if (usertype === 'admin' || usertype === 'user') {

        // if (!emailid || !password || !organisation || !name || !usertype || !campaign_name) {
        //     return res.status(400).json({ message: 'Incomplete details' });
        // }

        if (!emailid || !password || !organisation || !name || !usertype) {
            return res.status(400).json({ message: 'Incomplete details' });
        }

        bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Error hashing password: ' + err });
            }

            pool.getConnection((err, connection) => {
                if (err) {
                    console.error("Error getting the connection:", err);
                    return res.status(500).send('Server error');
                }

                const sqlInsertUser = 'INSERT INTO cmsusers(emailid, password, organisation, name, usertype, date) VALUES (?,?,?,?,?,?)';

                connection.query(sqlInsertUser, [emailid, hashedPassword, organisation, name, usertype, date], (err, result) => {
                    connection.release();
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Error inserting user data: ' + err });
                    }

                    // Fetch the campaignid based on the provided campaign_name
                    // const sqlFetchCampaignId = 'SELECT campaignid FROM campaign_table WHERE campaign_name = ?';

                    // connection.query(sqlFetchCampaignId, [campaign_name], (err, campaignResults) => {
                    //     connection.release();
                    //     if (err || campaignResults.length === 0) {
                    //         console.error(err);
                    //         return res.status(500).json({ message: 'Error fetching campaign data or campaign not found: ' + err });
                    //     }

                    //     const campaignId = campaignResults[0].campaignid;

                    //     // Insert emailid and campaignid into campaign_users table
                    //     const sqlInsertCampaignUser = 'INSERT INTO campaign_users(emailid, campaignid) VALUES (?,?)';

                    //     connection.query(sqlInsertCampaignUser, [emailid, campaignId], (err, _result) => {
                    //         connection.release();
                    //         if (err) {
                    //             console.error(err);
                    //             return res.status(500).json({ message: 'Error inserting into campaign_users: ' + err });
                    //         }

                    res.status(200).json({ message: 'User created' });
                    //     });
                    // });
                });
            });
        });
    }
});
//--------------------end of code-------------------------


//----------function for returning different multer configuration-------------
function upload(type) {
    switch (type) {
        case 'mind':
            return multer({
                storage: storage,
                limits: { fileSize: 10 * 1024 * 1024 }, // 30MB for .mind files
                // fileFilter: function (req, file, cb) {
                //     if (file.mimetype === "application/x-mind") {
                //         cb(null, true);
                //     } else {
                //         cb(new Error("Only .mind files are allowed"), false);
                //     }
                // }
            });

        case 'image':
            return multer({
                storage: storage,
                limits: { fileSize: 2 * 1024 * 1024 }, // 2MB for images
                fileFilter: function (req, file, cb) {
                    const allowedMimes = ["image/jpeg", "image/png", "image/jpg", "image/svg+xml"];
                    if (allowedMimes.includes(file.mimetype)) {
                        cb(null, true);
                    } else {
                        cb(new Error("Only jpeg, jpg, png, and svg files are allowed"), false);
                    }
                }
            });

        case 'gif':
            return multer({
                storage: storage,
                limits: { fileSize: 20 * 1024 * 1024 }, // 20MB for gifs
                fileFilter: function (req, file, cb) {
                    if (file.mimetype === "image/gif") {
                        cb(null, true);
                    } else {
                        cb(new Error("Only gif files are allowed"), false);
                    }
                }
            });

        default:
            throw new Error("Invalid type");
    }
}
//-------------end of multer configuration--------------------


//--------- api for deleting object from AWS s3 and data from AWS RDS-----------
app.delete('/delete-image/:campaignid/:pageno/:key', async (req, res) => {
    const { campaignid, pageno, key } = req.params;

    try {
        await deleteImage(campaignid, pageno, key);
        await deleteImageData(campaignid, pageno, key);
        res.status(200).send('Successfully deleted the image from S3 and its data from AWS RDS.');
    } catch (error) {
        console.error('Error deleting the image:', error);
        res.status(500).send('Failed to delete the image.');
    }
});


function deleteImageData(campaignid, pageno, key) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            let sql = 'DELETE FROM campaign_config where campaignid = ? AND pageno = ? AND `key` = ?';
            connection.query(sql, [campaignid, pageno, key], (err, results) => {
                connection.release();
                if (err) {
                    reject('Database error: ' + err);
                } else {
                    resolve(results);
                }
            });
        });
    });
}

function deleteImage(campaignid, pageno, key) {
    const params = {
        Bucket: bucketName,
        Key: `${campaignid}/${pageno}/${key}.jpg`,
    };

    return new Promise((resolve, reject) => {
        S3.deleteObject(params, function (err, data) {
            if (err) {
                reject(err);
            } else {
                resolve(data);
            }
        });
    });
}
// --------------------------api end--------------------------------------------

//----------------api for login and sending JWT token once verified successfully-----------------
const jwt = require('jsonwebtoken');
const { connect } = require('http2');
const JWT_SECRET = 'your_secret_key'; // Make sure to keep this secret
app.post('/newLogin', (req, res) => {
    const { emailid, password } = req.body;

    if (!emailid || !password) {
        return res.status(400).json({ message: 'Please provide email and password.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        // Verify the user's credentials and get the organisation description in one go
        const sql = `
            SELECT u.*, o.desc 
            FROM cmsusers u
            LEFT JOIN organisation o ON u.organisation = o.organisation 
            WHERE u.emailid = ?
        `;
        connection.query(sql, [emailid], (err, results) => {
            if (err) {
                console.error(err);
                connection.release();
                return res.status(500).json({ message: 'Error fetching user data: ' + err });
            }

            if (!results || results.length === 0) {
                connection.release();
                return res.status(401).json({ message: 'Invalid email or password.' });
            }

            // User exists; check the password now
            const user = results[0];
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    console.error(err);
                    connection.release();
                    return res.status(500).json({ message: 'Error comparing passwords: ' + err });
                }

                if (!isMatch) {
                    connection.release();
                    return res.status(401).json({ message: 'Invalid email or password.' });
                }

                // Passwords match; proceed based on the user type
                if (user.usertype === 'admin' || user.usertype === 'user') {
                    const campaignQuery = `
                        SELECT campaign_table.campaignid, campaign_table.campaign_name, campaign_table.scantype 
                        FROM campaign_users 
                        JOIN campaign_table ON campaign_users.campaignid = campaign_table.campaignid 
                        WHERE campaign_users.emailid = ?
                    `;
                    connection.query(campaignQuery, [emailid], (err, campaignResults) => {
                        connection.release();

                        if (err) {
                            console.error(err);
                            return res.status(500).json({ message: 'Error fetching campaign data: ' + err });
                        }

                        const campaigns_detail = campaignResults.map(campaign => {
                            return {
                                campaignid: campaign.campaignid,
                                campaign_name: campaign.campaign_name,
                                scantype: campaign.scantype
                            };
                        });

                        const token = jwt.sign({ emailid: emailid }, JWT_SECRET, { expiresIn: '1h' });

                        res.status(200).json({
                            token,
                            emailid: user.emailid,
                            name: user.name,
                            usertype: user.usertype,
                            organisation: user.organisation,
                            organisation_desc: user.desc, // Added organization description here
                            campaigns_detail
                        });
                    });
                } else if (user.usertype === 'superadmin') {
                    connection.release();

                    const token = jwt.sign({ emailid: emailid }, JWT_SECRET, { expiresIn: '1h' });

                    res.status(200).json({
                        token,
                        emailid: user.emailid,
                        name: user.name,
                        usertype: user.usertype,
                        organisation: user.organisation,
                        organisation_desc: user.desc, // Added organization description here
                    });
                } else {
                    connection.release();
                    res.status(401).json({ message: 'Invalid user role.' });
                }
            });
        });
    });
});
//---------------end of code-------------------


//------- api for deleting cms user account with emailid-------
app.delete('/deletecmsuser', (req, res) => {
    const emailid = req.body.emailid;

    if (!emailid) {
        return res.status(404).send('please enter emailid');
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        // First, delete entries for the emailid from the campaign_users table
        let deleteCampaignSql = 'DELETE FROM campaign_users WHERE emailid = ?';
        connection.query(deleteCampaignSql, [emailid], (err, campaignResults) => {
            if (err) {
                connection.release();
                console.error("Error deleting from campaign_users:", err);
                return res.status(500).send('Server error');
            }

            // Now, delete the user from the cmsusers table
            let deleteUserSql = 'DELETE FROM cmsusers WHERE emailid = ?';
            connection.query(deleteUserSql, [emailid], (err, userResults) => {
                connection.release();
                if (err) {
                    console.error("Error deleting from cmsusers:", err);
                    return res.status(500).send('Server error');
                }
                res.status(200).send('cmsuser account and related campaign entries deleted');
            });
        });
    });
});
//--------------------end of code----------------------

//----- api for adding customers (player,stage,timetaken with other details)------------------ 
// app.post('/addPlayerDetails', (req, res) => {
//     const currentMoment = moment().tz('Asia/Kolkata');
//     const date = currentMoment.format('YYYY-MM-DD HH:mm:ss');
//     const phonenumber = req.body.phonenumber;
//     const name = req.body.name;
//     const emailid = req.body.emailid;
//     const campaignid = req.body.campaignid;
//     const stagecompleted = req.body.stagecompleted;
//     const timetaken = req.body.timetaken;



//     if (!phonenumber || !name || !campaignid || !stagecompleted || !timetaken) {
//         return res.status(400).json({ message: 'Incomplete details' });
//     }

//     // First, check if the user already exists

//     pool.getConnection((err, connection) => {
//         if (err) {
//             console.error("Error getting the connection:", err);
//             return res.status(500).send('Server error');
//         }
//         const checkUserExists = 'SELECT * FROM custdata WHERE phonenumber = ? AND campaignid = ?';
//         connection.query(checkUserExists, [phonenumber, campaignid], (err, results) => {
//             connection.release();
//             if (err) {
//                 console.error(err);
//                 return res.status(500).json({ message: 'Error fetching the data:' + err });
//             }
//             // If results are returned, it means the user already exists
//             if (results && results.length > 0) {
//                 const time = results[0].timetaken;
//                 const totaltimetaken = time + timetaken;

//                 let updatesql = 'UPDATE custdata SET date = ?, stagecompleted = ? ,timetaken = ? WHERE phonenumber = ? AND campaignid =? ';
//                 connection.query(updatesql, [date, stagecompleted, totaltimetaken, phonenumber, campaignid], (err, results) => {
//                     connection.release();
//                     if (err) {
//                         console.error(err);
//                         return res.status(500).json({ message: 'Error updating the data:' + err });
//                     }
//                     return res.status(200).send('Player data updated in database');
//                 });
//             }
//             else {
//                 // If user doesn't exist, proceed to insert
//                 pool.getConnection((err, connection) => {
//                     if (err) {
//                         console.error("Error getting the connection:", err);
//                         return res.status(500).send('Server error');
//                     }
//                     const sql = 'INSERT INTO custdata (phonenumber,name,emailid,campaignid,date,stagecompleted,timetaken) VALUES (?, ?, ?, ?, ?, ?, ?)';
//                     connection.query(sql, [phonenumber, name, emailid, campaignid, date, stagecompleted, timetaken], (err, result) => {
//                         connection.release();
//                         if (err) {
//                             console.error(err);
//                             return res.status(500).json({ message: 'Error inserting data:' + err });
//                         }
//                         res.status(200).json({ message: 'Player Data inserted in Database' });
//                     });
//                 });
//             }
//         });
//     });
// });
//----------------end of code-----------------



//-----------api for getting the signed url of all pages under the campaignid at once with request of capmaignid,scantype---------------
/* app.get('/allsignedurls/:campaignid/:scantype', async (req, res) => {
    const { campaignid, scantype } = req.params;
    let keysData;

    try {
        if (scantype === 'imagescan') {
            keysData = await fetchKeysFromDB2(campaignid);
        } else if (scantype === 'QRscan') {
            keysData = await fetchKeysFromDB1(campaignid,scantype);
        } else {
            return res.status(400).send('Invalid scantype provided.');
        }

        const signedURLs = await Promise.all(keysData.map(data => getPresignedUrl(campaignid, data.pageno, data.key)));
        const response = keysData.map((data, index) => ({ pageno: data.pageno, key: data.key, value: signedURLs[index] }));

        res.status(200).send(response);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Failed to generate the signed URLs.');
    }
}); 


function fetchKeysFromDB2(campaignid) {
    return new Promise((resolve, reject) => {
        const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ?";
        connection.query(sql, [campaignid], (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
            }
        });
    });
}

function fetchKeysFromDB1(campaignid,scantype) {
    return new Promise((resolve, reject) => {
        const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ? AND scantype = ?";
        connection.query(sql, [campaignid,scantype], (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
            }
        });
    });
}

 function getPresignedUrl(campaignid, pageno, key) {
    return new Promise((resolve, reject) => {
      const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${key}`,
            Expires: 3600  // URL will be valid for 1 hour
        };
    
       S3.getSignedUrl('getObject', params, (err, url) => {
            if (err) {
                reject(err);
            } else {
                resolve(url);
            }
        });
    });
}   */

/* function getPresignedUrl(campaignid, pageno, key) {
    return new Promise((resolve, reject) => {
        let params;

        if (pageno < 100) {
            params = {
                Bucket: bucketName,
               // Key: `${campaignid}/${pageno}/${key}.jpg`,
                Key: `${campaignid}/${pageno}/${key}`,
                Expires: 3600  // URL will be valid for 1 hour
            };
        } else {
            params = {
                Bucket: bucketName,
                Key: `${campaignid}/${pageno}/${key}`,
                Expires: 3600  // URL will be valid for 1 hour
            };
        }

        S3.getSignedUrl('getObject', params, (err, url) => {
            if (err) {
                reject(err);
            } else {
                resolve(url);
            }
        });
    });
} */

//-------------------code ends----------------------

//-----------------------api for uploading gifs only--------------------------
app.post("/uploadgif/:campaignid/:pageno/:Key/:scantype", upload('gif').single('image'), async (req, res) => {
    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const Key = req.params.Key;
    const scantype = req.params.scantype;

    try {
        console.log(req.file);
        if (!req.file) {
            return res.status(400).send({
                msg: "No file provided for upload.",
            });
        }

        let fileExtension;
        switch (req.file.mimetype) {
            case "image/gif": fileExtension = "gif"; break;
            default: return res.status(400).send('Unsupported file type.');
        }

        const compositeKey = `${Key}.${fileExtension}`;   // Now it will just form as 'key.gif'
        let key = compositeKey;
        console.log(key);
        await uploadS3(req.file.buffer, campaignid, pageno, compositeKey);

        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = 'INSERT INTO campaign_config(campaignid,pageno,`key`,scantype) VALUES(?,?,?,?)';
            connection.query(sql, [campaignid, pageno, key, scantype], (err, result) => {
                connection.release();
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).send('Database error : ' + err);
                }
                res.send('gif uploaded and key stored in database');
            });
        });
    } catch (error) {
        console.error("Error while uploading:", error);
        res.status(500).send({
            msg: "Failed to upload the gif. Please try again later.",
        });
    }
});

const uploadS3 = (fileData, campaignid, pageno, compositeKey) => {
    return new Promise((resolve, reject) => {
        const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${compositeKey}`,
            Body: fileData,
        };
        S3.upload(params, (err, data) => {
            if (err) {
                console.log(err);
                return reject(err);
            }
            console.log(data);
            return resolve(data);
        });
    });
};
//---------------------end of code-----------------------    


//--------------code for uploading image(.png/.jpeg/.jpg) with campaignid,pageno,key & scantype------------
app.post("/uploadimage/:campaignid/:pageno/:key/:scantype", upload('image').single('image'), async (req, res) => {
    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const key = req.params.key;
    const scantype = req.params.scantype;

    try {
        console.log(req.file);
        if (!req.file) {
            return res.status(400).send({
                msg: "No file provided for upload.",
            });
        }

        // Determine the file extension from mimetype
        let fileExtension;
        switch (req.file.mimetype) {
            case "image/jpeg": fileExtension = "jpeg"; break;
            case "image/jpg": fileExtension = "jpg"; break;
            case "image/png": fileExtension = "png"; break;
            case "image/svg+xml": fileExtension = "svg"; break;
            default: return res.status(400).send('Unsupported image type.');
        }

        const compositeKey = `${key}.${fileExtension}`;

        await uploadToS3(req.file.buffer, campaignid, pageno, compositeKey);

        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }

            const sql = 'INSERT INTO campaign_config(campaignid,pageno,`key`,scantype) VALUES(?,?,?,?)';
            connection.query(sql, [campaignid, pageno, compositeKey, scantype], (err, result) => {
                connection.release();
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).send('Database error : ' + err);
                }
                res.send('Image uploaded and key stored in database');
            });

        });
    } catch (error) {
        console.error("Error while uploading:", error);
        res.status(500).send({
            msg: "Failed to upload the image. Please try again later.",
        });
    }
});

// Function for storing image in AWS S3
const uploadToS3 = (fileData, campaignid, pageno, compositeKey) => {
    return new Promise((resolve, reject) => {
        const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${compositeKey}`,
            Body: fileData,
        };
        S3.upload(params, (err, data) => {
            if (err) {
                console.log(err);
                return reject(err);
            }
            console.log(data);
            return resolve(data);
        });
    });
};
//------------------------end of code------------------------

//-----------------api for getting all the signedurls orderby pageno after checking the status,enddate,startdate---------------------- 
app.get('/allsignedurls/:campaignid/:scantype', async (req, res) => {
    try {
        const { campaignid, scantype } = req.params;
        const currentMoment = moment().tz('Asia/Kolkata');
        // const currentDate = currentMoment.format('YYYY-MM-DD');
        const currentDate = currentMoment;

        const results = await checkCampaignStatus(campaignid);

        const startDate = moment(results[0].formatted_startdate, "YYYY-MM-DD");
        const endDate = moment(results[0].formatted_enddate, 'YYYY-MM-DD').endOf('day');

        if (results[0].status === 'inactive' || !currentDate.isBetween(startDate, endDate, undefined, '[]')) {
            return res.status(400).send('Cannot launch campaign');
        }

        let keysData;

        if (scantype === 'imagescan') {
            keysData = await fetchKeysFromDB2(campaignid);
        } else if (scantype === 'QRscan') {
            keysData = await fetchKeysFromDB1(campaignid, scantype);
        } else {
            return res.status(400).send('Invalid scantype provided.');
        }

        const signedURLs = await Promise.all(keysData.map(data => getPresignedUrl(campaignid, data.pageno, data.key)));
        const response = keysData.map((data, index) => ({ pageno: data.pageno, key: data.key, value: signedURLs[index] }));
        // const response = keysData.map((data, index) => ({ pageno: data.pageno,  value: signedURLs[index] }));
        // Group by page number
        const groupedResponse = response.reduce((accumulator, current) => {
            (accumulator[current.pageno] = accumulator[current.pageno] || []).push({ key: current.key, value: current.value });
            return accumulator;                                                 // ({ [current.key] : current.value })
        }, {});

        res.status(200).send(groupedResponse);

    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Failed to generate the signed URLs.');
    }
});

async function checkCampaignStatus(campaignid) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                reject('Error getting the connection: ' + err);
            } else {
                const checksql = 'SELECT DATE_FORMAT(startdate, "%Y-%m-%d") AS formatted_startdate,DATE_FORMAT(enddate, "%Y-%m-%d") AS formatted_enddate, status FROM campaign_table WHERE campaignid = ?';
                connection.query(checksql, [campaignid], (err, results) => {
                    connection.release();
                    if (err) {
                        reject('Error querying the database: ' + err);
                    } else {
                        resolve(results);
                    }
                });
            }
        });
    });
}


function fetchKeysFromDB2(campaignid) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ?";
            connection.query(sql, [campaignid], (err, results) => {
                connection.release();
                if (err) {
                    reject(err);
                } else {
                    resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
                }
            });
        });
    });
}

function fetchKeysFromDB1(campaignid, scantype) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ? AND scantype = ?";
            connection.query(sql, [campaignid, scantype], (err, results) => {
                connection.release();
                if (err) {
                    reject(err);
                } else {
                    resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
                }
            });
        });
    });

}

function getPresignedUrl(campaignid, pageno, key) {
    return new Promise((resolve, reject) => {
        const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${key}`,
            Expires: 3600  // URL will be valid for 1 hour
        };

        S3.getSignedUrl('getObject', params, (err, url) => {
            if (err) {
                reject(err);
            } else {
                resolve(url);
            }
        });
    });
}
//---------------------end of code------------------




//--api for updating image in S3 bucket and checks in database if key already exists
// app.post("/updateimage/:campaignid/:pageno/:key/:scantype", upload('image').single('image'), async (req, res) => {
//     const campaignid = req.params.campaignid;
//     const pageno = req.params.pageno;
//     const key = req.params.key;
//     const scantype = req.params.scantype;

//     try {
//         if (!req.file) {
//             return res.status(400).send({
//                 msg: "No file provided for upload.",
//             });
//         }

//         // Determine the file extension from mimetype
//         let fileExtension;
//         switch (req.file.mimetype) {
//             case "image/jpeg":
//                 fileExtension = "jpeg";
//                 break;
//             case "image/jpg":
//                 fileExtension = "jpg";
//                 break;
//             case "image/png":
//                 fileExtension = "png";
//                 break;
//             default:
//                 return res.status(400).send('Unsupported image type.');
//         }

//         const compositeKey = `${key}.${fileExtension}`;

//         await uploadtoS3(req.file.buffer, campaignid, pageno, compositeKey);

//         const keyExists = await checkKeyInDB(campaignid, pageno, compositeKey);
//         if (!keyExists) {

//             pool.getConnection((err, connection) => {
//                 if (err) {
//                     console.error("Error getting the connection:", err);
//                     return res.status(500).send('Server error');
//                 }

//                 const sql = 'INSERT INTO campaign_config(campaignid,pageno,`key`,scantype) VALUES(?,?,?,?)';
//                 connection.query(sql, [campaignid, pageno, compositeKey, scantype], (err, result) => {
//                     connection.release();
//                     if (err) {
//                         console.error('Database error:', err);
//                         return res.status(500).send('Database error: ' + err);
//                     }
//                     res.status(200).send('Image uploaded and key stored in database');
//                 });
//             });
//         } else {
//             res.status(200).send({ message: 'New Image uploaded' });
//         }

//     } catch (error) {
//         console.error("Error while uploading:", error);
//         res.status(500).send({
//             msg: "Failed to upload the image. Please try again later.",
//         });
//     }
// });

// // Function to check if the key exists in the database
// const checkKeyInDB = (campaignid, pageno, compositeKey) => {
//     return new Promise((resolve, reject) => {
//         pool.getConnection((err, connection) => {
//             if (err) {
//                 console.error("Error getting the connection:", err);
//                 return res.status(500).send('Server error');
//             }
//             const sql = 'SELECT COUNT(*) as count FROM campaign_config WHERE campaignid = ? AND pageno = ? AND `key` = ?';
//             connection.query(sql, [campaignid, pageno, compositeKey], (err, result) => {
//                 connection.release();
//                 if (err) {
//                     reject(err);
//                 } else {
//                     resolve(result[0].count > 0);  // true if key is already in the database
//                 }
//             });
//         });
//     });
// };

// const uploadtoS3 = (fileData, campaignid, pageno, compositeKey) => {
//     return new Promise((resolve, reject) => {
//         const params = {
//             Bucket: bucketName,
//             Key: `${campaignid}/${pageno}/${compositeKey}`,
//             Body: fileData,
//         };
//         S3.upload(params, (err, data) => {
//             if (err) {
//                 console.log(err);
//                 return reject(err);
//             }
//             console.log(data);
//             return resolve(data);
//         });
//     });
// };
//----------------------------end of code--------------------------

//----api for creating new page and returning empty array as newly page will not have any object------
// app.post('/createpage/:campaignid/:pageno', async (req, res) => {
//     const campaignid = req.params.campaignid;
//     const pageno = req.params.pageno;

//     const fullKey = `${campaignid}/${pageno}/`;

//     const createParams = {
//         Bucket: bucketName,
//         Key: fullKey,
//         Body: ''
//     };

//     const listParams = {
//         Bucket: bucketName,
//         Prefix: fullKey
//     };

//     try {
//         // Create the "subfolder"
//         await S3.putObject(createParams).promise();

//         // List objects inside the "subfolder"
//         const data = await S3.listObjectsV2(listParams).promise();
//         const objects = data.Contents.map(obj => obj.Key);

//         if (objects.length === 1 && objects[0] === fullKey) {
//             res.status(200).json({ [pageno]: [] });
//         } else {
//             const urls = await Promise.all(objects.filter(key => key !== fullKey).map(key => getUrl(key)));
//             res.status(200).json({ [pageno]: urls });
//         }

//     } catch (error) {
//         console.error('Error:', error);
//         res.status(500).send('Failed to process the request');
//     }
// });


// const getUrl = (fullKey) => {
//     return new Promise((resolve, reject) => {
//         const params = {
//             Bucket: bucketName,
//             Key: fullKey,
//             Expires: 3600  // URL will be valid for 1 hour
//         };

//         S3.getSignedUrl('getObject', params, (err, url) => {
//             if (err) {
//                 reject(err);
//             } else {
//                 resolve(url);
//             }
//         });
//     });
// }
//---------------------------end of code------------------------


//-------------------update gifs---------------------------
app.post("/updategif/:campaignid/:pageno/:Key/:scantype", upload('gif').single('image'), async (req, res) => {
    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const Key = req.params.Key;
    const scantype = req.params.scantype;

    try {
        console.log(req.file);
        if (!req.file) {
            return res.status(400).send({
                msg: "No file provided for upload.",
            });
        }

        let fileExtension;
        switch (req.file.mimetype) {
            case "image/gif": fileExtension = "gif"; break;
            default: return res.status(400).send('Unsupported file type.');
        }

        const compositeKey = `${Key}.${fileExtension}`;   // Now it will just form as 'key.gif'
        let key = compositeKey;
        //  console.log(key);
        await loadS3(req.file.buffer, campaignid, pageno, compositeKey);

        const keyExists = await checkkeyinDB(campaignid, pageno, compositeKey);

        if (!keyExists) {

            pool.getConnection((err, connection) => {
                if (err) {
                    console.error("Error getting the connection:", err);
                    return res.status(500).send('Server error');
                }

                const sql = 'INSERT INTO campaign_config(campaignid,pageno,`key`,scantype) VALUES(?,?,?,?)';
                connection.query(sql, [campaignid, pageno, compositeKey, scantype], (err, result) => {
                    connection.release();
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).send('Database error: ' + err);
                    }
                    res.status(200).send('gif uploaded and key stored in database');
                });
            });

        } else {
            res.status(200).send({ message: 'New gif uploaded' });
        }
    } catch (error) {
        console.error("Error while uploading:", error);
        res.status(500).send({
            msg: "Failed to upload the gif. Please try again later.",
        });
    }
});


const loadS3 = (fileData, campaignid, pageno, compositeKey) => {
    return new Promise((resolve, reject) => {
        const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${compositeKey}`,
            Body: fileData,
        };
        S3.upload(params, (err, data) => {
            if (err) {
                console.log(err);
                return reject(err);
            }
            console.log(data);
            return resolve(data);
        });
    });
};

const checkkeyinDB = (campaignid, pageno, compositeKey) => {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = 'SELECT COUNT(*) as count FROM campaign_config WHERE campaignid = ? AND pageno = ? AND `key` = ?';
            connection.query(sql, [campaignid, pageno, compositeKey], (err, result) => {
                connection.release();
                if (err) {
                    reject(err);
                } else {
                    resolve(result[0].count > 0);  // true if key is already in the database
                }
            });
        });
    });
};
//----------------code ends------------------


//-----------reset password by superadmin-------------------
app.post('/updatepassword', async (req, res) => {
    const { emailid, newpassword } = req.body;

    // Check if email and new password are provided
    if (!emailid || !newpassword) {
        return res.status(400).send('Email ID and new password are required');
    }

    try {
        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newpassword, saltRounds);

        // Update the password in the database
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            let sql = 'UPDATE cmsusers SET password = ? WHERE emailid = ?';
            connection.query(sql, [hashedNewPassword, emailid], (err, results) => {
                connection.release();
                if (err) {
                    return res.status(500).send('Password update failed: ' + err);
                }

                // Check if password is updated (affectedRows is a property that tells if rows were changed)
                if (results.affectedRows === 0) {
                    return res.status(400).send('No user found with the provided email ID');
                }
                res.status(200).json('password updated');
            });
        });
    } catch (error) {
        res.status(500).send('Internal server error');
    }
});
//-------------end of code--------------




//------------api for sending otp------------
app.post('/sendotp/:mobilenumber', (req, res) => {
    const { mobilenumber } = req.params;

    if (!mobilenumber) {
        return res.status(400).send('Mobile number is required.');
    }
    //10 digit mobile number will be received in the request
    const appendmobilenumber = '+91' + mobilenumber;
    const otpURL = `https://control.msg91.com/api/v5/otp?template_id=${templateId}&mobile=${appendmobilenumber}`;

    request.post(otpURL, {
        headers: {
            'authkey': authKey
        }
    }, (error, response, body) => {
        if (error) {
            console.error('Error sending OTP:', error);
            return res.status(500).send('Failed to send OTP.');
        }

        const responseBody = JSON.parse(body);
        if (responseBody.type === "success") {
            res.status(200).send('OTP sent successfully.');
        } else {
            res.status(400).send(responseBody.message);
        }
    });
});
//--------------end of code--------------------

//-------------code for verifying otp----------------
app.get('/verifyOtp/:mobilenumber/:otp', (req, res) => {
    const mobilenumber = req.params.mobilenumber;
    const otp = req.params.otp;

    if (!mobilenumber) {
        return res.status(400).send('Mobile number is required.');
    }
    //10 digit mobile number will be received in the request
    const appendmobilenumber = '+91' + mobilenumber;
    const verifyOtpURL = `https://control.msg91.com/api/v5/otp/verify?&mobile=${appendmobilenumber}&otp=${otp}`;

    request.post(verifyOtpURL, {
        headers: {
            'authkey': authKey
        }
    }, (error, response, body) => {
        if (error) {
            console.error('Error verifying OTP:', error);
            return res.status(500).send('Failed to verify OTP.');
        }

        const responseBody = JSON.parse(body);
        if (responseBody.type === "success") {
            res.status(200).send('OTP verified successfully.');
        } else {
            res.status(400).send(responseBody.message);
        }
    });

});
//--------------end of code--------------------

/* // -------api for getting the campaign details as asked in slack----------
app.get('/campaigndetails/:emailid',(req , res) => {
   const { emailid } = req.params;
   pool.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting the connection:", err);
      return res.status(500).send('Server error');
    }
   const sql = 'SELECT campaignid,organisation,scantype,campaign_name FROM campaign_table WHERE emailid = ?';
   connection.query(sql,emailid,(err,results) => {
    connection.release();
   if(err){
      res.status(400).json({err});
   }
   res.status(200).send(results);
  });
});
});
//------------end of code-------------------------
 */

//--------api for uploading converting image to .mind image---------------------
/* app.post('/compile-upload/:campaignid/:pageno/:Key/:scantype', upload('mind').single('image'), async (req, res) => {
    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const Key = req.params.Key;
    const scantype = req.params.scantype;

    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }

    const image = await loadImage(req.file.buffer);

    try {
        const { OfflineCompiler } = await import('./mind-ar-js-master/src/image-target/offline-compiler.js');
        const compiler = new OfflineCompiler();
        await compiler.compileImageTargets([image], console.log);
        const buffer = compiler.exportData();

        const compositeKey = `${Key}.mind`;

        // Check if image with existing name is in the database
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const checkSql = 'SELECT COUNT(*) as count FROM campaign_config WHERE `key` = ?';
            connection.query(checkSql, [compositeKey], (err, results) => {
                connection.release();
                if (err) {
                    console.error('Database check error:', err);
                    return res.status(500).json('Database error: ' + err);
                }

                // If image does not exist in the database
                if (results[0].count === 0) {
                    // Upload the file to S3
                    const params = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKey}`,
                        Body: buffer,
                        ContentType: 'application/octet-stream'  // Since it's a binary file
                    };

                    S3.upload(params, (err, data) => {
                        if (err) {
                            return res.status(500).json('Error uploading file to S3: ' + err.message);
                        }

                        // Insert into database
                        pool.getConnection((err, connection) => {
                            if (err) {
                                console.error("Error getting the connection:", err);
                                return res.status(500).send('Server error');
                            }
                            const insertSql = 'INSERT INTO campaign_config(campaignid,pageno,`key`,scantype) VALUES(?,?,?,?)';
                            connection.query(insertSql, [campaignid, pageno, compositeKey, scantype], (err, result) => {
                                connection.release();
                                if (err) {
                                    console.error('Database insertion error:', err);
                                    return res.status(500).send('Database error: ' + err);
                                }
                                res.status(200).json('Image converted, uploaded to S3, and key stored in database');
                            });
                        });
                    });
                } else {
                    // If image already exists in the database, overwrite in S3
                    const params = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKey}`,
                        Body: buffer,
                        ContentType: 'application/octet-stream'  // Since it's a binary file
                    };

                    S3.upload(params, (err, data) => {
                        if (err) {
                            return res.status(500).send('Error overriding file in S3: ' + err.message);
                        }
                        res.status(200).json('Image converted and overridden in S3');
                    });
                }
            });
        });
    } catch (error) {
        console.error("Failed to load module or process:", error);
        res.status(500).json('Internal Server Error');
    }
}); */
//------------------------------end of code---------------------------


// -------api for getting the campaign details as asked in slack (bikram)----------
app.get('/campaigndetails/:emailid/:usertype', (req, res) => {
    const { emailid, usertype } = req.params;

    if (usertype === 'superadmin') {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = 'SELECT campaignid,organisation,scantype,campaign_name,emailid FROM campaign_table';
            connection.query(sql, emailid, (err, results) => {
                connection.release();
                if (err) {
                    res.status(400).json({ err });
                }
                res.status(200).send(results);
            });
        });
    }

    if (usertype === 'admin' || usertype === 'user') {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql1 = 'SELECT organisation FROM cmsusers WHERE emailid = ?';
            connection.query(sql1, [emailid], (err, results1) => {
                connection.release();
                if (err) {
                    connection.release();
                    return res.status(400).json({ err });
                }

                const organisation = results1[0].organisation;
                const sql2 = 'SELECT campaignid,scantype,campaign_name,emailid FROM campaign_table WHERE organisation = ?';
                connection.query(sql2, [organisation], (err, results2) => {
                    connection.release();
                    if (err) {
                        return res.status(400).json({ err });
                    }
                    res.status(200).send(results2);
                });
            });
        });
    }
});
//----------------end of code-------------------------



//----------api for getting the list of organisation table -------------
app.get('/organisationlist/:emailid/:usertype', (req, res) => {
    const { emailid, usertype } = req.params;
    if (usertype === 'superadmin') {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            let sql = 'SELECT * FROM organisation';
            connection.query(sql, (err, results) => {
                connection.release();
                if (err) {
                    res.status(404).json({ message: err })
                }
                res.status(200).json(results);

            });
        });
    }
    if (usertype === 'admin' || usertype === 'user') {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql1 = 'SELECT organisation FROM cmsusers WHERE emailid = ?';
            connection.query(sql1, [emailid], (err, results1) => {
                connection.release();
                if (err) {
                    connection.release();
                    return res.status(400).json({ err });
                }

                const organisation = results1[0].organisation;
                const sql2 = 'SELECT * FROM organisation WHERE organisation = ?';
                connection.query(sql2, [organisation], (err, results2) => {
                    connection.release();
                    if (err) {
                        return res.status(400).json({ err });
                    }
                    res.status(200).send(results2);
                });
            });
        });
    }
});
//------------end of code----------------



//---------unique organisation-----------------
app.post('/organisation', (req, res) => {
    const { organisation, desc } = req.body;
    const currentMoment = moment().tz('Asia/Kolkata');
    const date = currentMoment.format('YYYY-MM-DD HH:mm:ss');

    if (!organisation || !desc) {
        return res.status(400).json({ message: 'Both name and description are required.' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        // Check if organisation already exists (case insensitive)
        let checkSql = 'SELECT * FROM organisation WHERE LOWER(organisation) = LOWER(?)';
        connection.query(checkSql, [organisation], (err, results) => {
            if (err) {
                connection.release();
                return res.status(500).json({ message: 'Error checking data: ' + err });
            }

            if (results.length > 0) {
                connection.release();
                return res.status(400).json({ message: 'Organisation already exists.' });
            } else {
                // Insert organisation if not exists
                let insertSql = 'INSERT INTO organisation (organisation, `desc`, createddate) VALUES (?, ?, ?)';
                connection.query(insertSql, [organisation, desc, date], (err, results) => {
                    connection.release();
                    if (err) {
                        return res.status(500).json({ message: 'Error inserting data: ' + err });
                    }
                    res.status(200).send('Data inserted');
                });
            }
        });
    });
});
//----------end of code-------------------


//--------api for uploading converting image to .mind image and saving the original (.png/jpeg/.jpg) as well---------------------
/* app.post('/compile-upload/:campaignid/:pageno/:Key/:scantype', upload('mind').single('image'), async (req, res) => {
    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const Key = req.params.Key;
    const scantype = req.params.scantype;

    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }

    const image = await loadImage(req.file.buffer);

    try {
        const { OfflineCompiler } = await import('./mind-ar-js-master/src/image-target/offline-compiler.js');
        const compiler = new OfflineCompiler();
        await compiler.compileImageTargets([image], console.log);
        const buffer = compiler.exportData();

        const compositeKeyMind = `${Key}.mind`;
        const originalImageExtension = req.file.originalname.split('.').pop();
        const compositeKeyImage = `${Key}.${originalImageExtension}`; 

        pool.getConnection(async (err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                connection.release();
                return res.status(500).send('Server error');
            }

            const checkSql = 'SELECT COUNT(*) as count FROM campaign_config WHERE `key` = ?';
            connection.query(checkSql, [compositeKeyMind], async (err, results) => {
                if (err) {
                    console.error('Database check error:', err);
                    connection.release();
                    return res.status(500).json('Database error: ' + err);
                }

                // Create a helper to handle uploads and db inserts.
                const handleUploadAndInsert = async (s3Params, dbKey) => {
                    await new Promise((resolve, reject) => {
                        S3.upload(s3Params, (err, data) => {
                            if (err) reject(err);
                            else resolve(data);
                        });
                    });

                    const insertSql = 'INSERT INTO campaign_config(campaignid, pageno, `key`, scantype) VALUES (?, ?, ?, ?)';
                    await new Promise((resolve, reject) => {
                        connection.query(insertSql, [campaignid, pageno, dbKey, scantype], (err, result) => {
                            if (err) reject(err);
                            else resolve(result);
                        });
                    });
                };

                // If image does not exist in the database
                if (results[0].count === 0) {
                    const mindParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyMind}`,
                        Body: buffer,
                        ContentType: 'application/octet-stream'  // Since it's a binary file
                    };
                    const imageParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyImage}`,
                        Body: req.file.buffer,
                        ContentType: req.file.mimetype
                    };

                    try {
                        await Promise.all([
                            handleUploadAndInsert(mindParams, compositeKeyMind),
                            handleUploadAndInsert(imageParams, compositeKeyImage)
                        ]);

                        res.status(200).send('Both .mind and image file got uploaded successfully');
                    } catch (e) {
                        console.error("Upload or Database Insert Error:", e);
                        res.status(500).send('Error handling uploads or database insert: ' + e.message);
                    }
                } else {
                    // If image already exists in the database, overwrite in S3
                    const mindParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyMind}`,
                        Body: buffer,
                        ContentType: 'application/octet-stream'  // Since it's a binary file
                    };

                    S3.upload(mindParams, (err, data) => {
                        if (err) {
                            res.status(500).send('Error overriding .mind file in S3: ' + err.message);
                        } else {
                            res.status(200).json('Image converted and overridden in S3');
                        }
                    });
                }
                connection.release();
            });
        });
    } catch (error) {
        console.error("Failed to load module or process:", error);
        res.status(500).json('Internal Server Error');
    }
}); */
//----------------end of code-----------------------------




//-code for converting (.png/.jpg/.jpeg) file to .mind image and storing in database and overriding if the same key is present in database----
app.post('/compile-upload/:campaignid/:pageno/:Key/:scantype', upload('mind').single('image'), async (req, res) => {

    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const Key = req.params.Key;
    const scantype = req.params.scantype;

    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }

    const image = await loadImage(req.file.buffer);

    try {
        const { OfflineCompiler } = await import('./mind-ar-js-master/src/image-target/offline-compiler.js');
        const compiler = new OfflineCompiler();
        await compiler.compileImageTargets([image], console.log);
        const buffer = compiler.exportData();

        const compositeKeyMind = `${Key}.mind`;
        const originalImageExtension = req.file.originalname.split('.').pop();
        const compositeKeyImage = `${Key}.${originalImageExtension}`;
        // Create a helper to handle S3 uploads.
        const handleUpload = async (s3Params) => {
            return new Promise((resolve, reject) => {
                S3.upload(s3Params, (err, data) => {
                    if (err) reject(err);
                    else resolve(data);
                });
            });
        };

        pool.getConnection(async (err, connection) => {

            if (err) {
                console.error("Error getting the connection:", err);
                connection.release();
                return res.status(500).send('Server error');
            }

            const checkSql = 'SELECT COUNT(*) as count FROM campaign_config WHERE campaignid = ? AND pageno = ? AND `key` = ?';
            connection.query(checkSql, [campaignid, pageno, compositeKeyMind], async (err, results) => {
                if (err) {
                    console.error('Database check error:', err);
                    connection.release();
                    return res.status(500).json('Database error: ' + err);
                }

                // Create a helper to handle uploads and db inserts.
                const handleUploadAndInsert = async (s3Params, dbKey) => {
                    await new Promise((resolve, reject) => {
                        S3.upload(s3Params, (err, data) => {
                            if (err) reject(err);
                            else resolve(data);
                        });
                    });

                    const insertSql = 'INSERT INTO campaign_config(campaignid, pageno, `key`, scantype) VALUES (?, ?, ?, ?)';
                    await new Promise((resolve, reject) => {
                        connection.query(insertSql, [campaignid, pageno, dbKey, scantype], (err, result) => {
                            if (err) reject(err);
                            else resolve(result);
                        });
                    });
                };

                // If image does not exist in the database
                if (results[0].count === 0) {

                    const mindParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyMind}`,
                        Body: buffer,
                        ContentType: 'application/octet-stream'  // Since it's a binary file
                    };
                    const imageParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyImage}`,
                        Body: req.file.buffer,
                        ContentType: req.file.mimetype
                    };

                    try {
                        await Promise.all([
                            handleUploadAndInsert(mindParams, compositeKeyMind),
                            handleUploadAndInsert(imageParams, compositeKeyImage)
                        ]);

                        res.status(200).send('Both .mind and image file got uploaded successfully');
                    } catch (e) {
                        console.error("Upload or Database Insert Error:", e);
                        res.status(500).send('Error handling uploads or database insert: ' + e.message);
                    }
                } else {
                    // If image already exists in the database, overwrite in S3
                    const mindParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyMind}`,
                        Body: buffer,
                        ContentType: 'application/octet-stream'
                    };

                    const imageParams = {
                        Bucket: bucketName,
                        Key: `${campaignid}/${pageno}/${compositeKeyImage}`,
                        Body: req.file.buffer,
                        ContentType: req.file.mimetype
                    };

                    try {
                        await Promise.all([
                            handleUpload(mindParams),
                            handleUpload(imageParams)
                        ]);
                        res.status(200).send('Both .mind and original image file got overridden in S3');
                    } catch (e) {
                        console.error("Upload Error:", e);
                        res.status(500).send('Error overriding files in S3: ' + e.message);
                    }
                }
                connection.release();
            });

        });
    } catch (error) {
        console.error("Failed to load module or process:", error);
        res.status(500).json('Internal Server Error');
    }
});
//-------------------------end of code-------------------------------------



//-----code for getting allsigned urls based on scantype and campaignid ----------------------
// app.get('/allsignedurl/:campaignid/:scantype', async (req, res) => {
//     const { campaignid, scantype } = req.params;

//     try {
//         const keysData = await fetchKeysFromDB(campaignid, scantype);

//         const signedURLs = await Promise.all(keysData.map(data => getPresignedUrl(campaignid, data.pageno, data.key)));
//         const response = keysData.map((data, index) => ({ pageno: data.pageno, key: data.key, value: signedURLs[index] }));

//         // Group by page number
//         const groupedResponse = response.reduce((accumulator, current) => {
//             (accumulator[current.pageno] = accumulator[current.pageno] || []).push({ key: current.key, value: current.value });
//             return accumulator;
//         }, {});

//         res.status(200).send(groupedResponse);
//     } catch (error) {
//         console.error('Error:', error);
//         res.status(500).send('Failed to generate the signed URLs.');
//     }
// });

// function fetchKeysFromDB(campaignid, scantype) {
//     return new Promise((resolve, reject) => {
//         pool.getConnection((err, connection) => {
//             if (err) {
//                 console.error("Error getting the connection:", err);
//                 reject(err); // Reject the promise with error
//                 return; // Important: Exit the function to avoid further processing
//             }
//             const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ? AND scantype = ?";
//             connection.query(sql, [campaignid, scantype], (err, results) => {
//                 connection.release();
//                 if (err) {
//                     reject(err);
//                 } else {
//                     resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
//                 }
//             });
//         });
//     });
// }

// function getPresignedUrl(campaignid, pageno, key) {
//     return new Promise((resolve, reject) => {
//         const params = {
//             Bucket: bucketName,
//             Key: `${campaignid}/${pageno}/${key}`,
//             Expires: 3600  // URL will be valid for 1 hour
//         };

//         S3.getSignedUrl('getObject', params, (err, url) => {
//             if (err) {
//                 reject(err);
//             } else {
//                 resolve(url);
//             }
//         });
//     });
// }
//------------end of code--------------------------------------------


//-----------api for gatting the list of customers(players) based on campaignid---------------- 
app.get('/getPlayersList/:campaignid', async (req, res) => {
    const campaignid = req.params.campaignid;
    if (!campaignid) {
        return res.status(400).send('campaignid is required');
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }
        const sql = 'SELECT * FROM custdata WHERE campaignid = ?';
        connection.query(sql, [campaignid], (err, results) => {
            connection.release();
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Error fetching data: ' + err });
            }
            res.status(200).json(results);
        });
    });
});
//----------end of code---------------------


//-----api for getting the list of customers(players) based on customer/players(phonenumber)---------------- 
// app.get('/getPlayersInfo/:phonenumber', async (req, res) => {
//     const phonenumber = req.params.phonenumber;
//     if (!phonenumber) {
//         return res.status(400).send('phonenumber is required');
//     }

//     pool.getConnection((err, connection) => {
//         if (err) {
//             console.error("Error getting the connection:", err);
//             return res.status(500).send('Server error');
//         }
//         const sql = 'SELECT * FROM custdata WHERE phonenumber = ?';
//         connection.query(sql, [phonenumber], (err, results) => {
//             connection.release();
//             if (err) {
//                 console.error(err);
//                 return res.status(500).json({ message: 'Error fetching data: ' + err });
//             }
//             res.status(200).json(results);
//         });
//     });
// });
//----------end of code---------------------


//-----api for deleting the players(end user) by phonenumber and campaignid-----------
app.delete('/deletePlayer/:phonenumber/:campaignid', async (req, res) => {
    const campaignid = req.params.campaignid;
    const phonenumber = req.params.phonenumber;
    if (!campaignid || !phonenumber) {
        return res.status(400).send('incomplete details');
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }
        const sql = 'DELETE FROM custdata WHERE phonenumber = ? AND campaignid = ?';
        connection.query(sql, [phonenumber, campaignid], (err, results) => {
            connection.release();
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Error fetching data: ' + err });
            }
            res.status(200).json(`Player data with ${phonenumber} deleted`);
        });
    });
});
//------------------end of code-------------------------------------


//-----api for getting the list of user/admin of that organisation---------
// app.get('/userslist/:organisation', async (req, res) => {
//     const { organisation } = req.params;
//     if (!organisation) {
//         return res.status(400).send('organisation is mandatory');
//     }
//     pool.getConnection((err, connection) => {
//         if (err) {
//             console.error("Error getting the connection:", err);
//             return res.status(500).send('Server error');
//         }
//         const sql = 'SELECT emailid,name,usertype,date FROM cmsusers WHERE organisation = ?';
//         connection.query(sql, [organisation], (err, results) => {
//             connection.release();
//             if (err) {
//                 console.error(err);
//                 return res.status(500).json({ message: 'Error fetching data: ' + err });
//             }
//             res.status(200).json(results);
//         });
//     });
// });
//--------------------end of code-----------------


//------api for creating organisation with contactname,contactphone,emailid,logo-------------
// app.post("/createOrganisation", upload('image').single('image'), async (req, res) => {
//     const organisation = req.body.organisation;
//     const desc = req.body.desc;
//     const name = req.body.name;
//     const phoneno = req.body.phoneno;
//     const emailid = req.body.emailid;
//     const key = req.body.key;
//     // const logo = req.params.logo;

//     try {
//         console.log(req.file);
//         if (!req.file) {
//             return res.status(400).send({
//                 msg: "No file provided for upload.",
//             });
//         }

//         // Determine the file extension from mimetype
//         let fileExtension;
//         switch (req.file.mimetype) {
//             case "image/jpeg": fileExtension = "jpeg"; break;
//             case "image/jpg": fileExtension = "jpg"; break;
//             case "image/png": fileExtension = "png"; break;
//             default: return res.status(400).send('Unsupported image type.');
//         }

//         // const compositeKey = `${req.file.originalname}.${fileExtension}`;
//         const compositeKey = `${key}.${fileExtension}`;

//         await uploadlogoS3(req.file.buffer, organisation, compositeKey);

//         pool.getConnection((err, connection) => {
//             if (err) {
//                 console.error("Error getting the connection:", err);
//                 return res.status(500).send('Server error');
//             }

//             let insertSql = 'INSERT INTO organisation (organisation,`desc`, name, emailid, phoneno, logo) VALUES (?, ?, ?, ?, ?, ?)';
//             connection.query(insertSql, [organisation, desc, name, emailid, phoneno, compositeKey], (err, results) => {
//                 connection.release();
//                 if (err) {
//                     return res.status(500).json({ message: 'Error inserting data: ' + err });
//                 }
//                 res.status(200).send('Data inserted');
//             });
//         });
//     } catch (error) {
//         console.error("Error while uploading:", error);
//         res.status(500).send({
//             msg: "Failed to upload the image. Please try again later.",
//         });
//     }
// });

// Function for storing image in AWS S3
// const uploadlogoS3 = (fileData, organisation, compositeKey) => {
//     return new Promise((resolve, reject) => {
//         const params = {
//             Bucket: bucketName,
//             Key: `${`logo's`}/${organisation}/${compositeKey}`,
//             Body: fileData,
//         };
//         S3.upload(params, (err, data) => {
//             if (err) {
//                 console.log(err);
//                 return reject(err);
//             }
//             console.log(data);
//             return resolve(data);
//         });
//     });
// };
//----------------end of code-----------------



//--------------api for updating organisation phoneno,emailid,image,key,name-----------------
// app.post("/updateOrganisation", upload('image').single('image'), async (req, res) => {
//     const { organisation, desc, name, phoneno, emailid, key } = req.body;
//     let fieldsToUpdate = {};
//     let queries = [];
//     let values = [];

//     // Check what was provided to update
//     if (desc) {
//         fieldsToUpdate.desc = desc;
//     }
//     if (name) {
//         fieldsToUpdate.name = name;
//     }
//     if (phoneno) {
//         fieldsToUpdate.phoneno = phoneno;
//     }
//     if (emailid) {
//         fieldsToUpdate.emailid = emailid;
//     }

//     // Constructing the query based on the fields provided
//     for (const [key, value] of Object.entries(fieldsToUpdate)) {
//         // queries.push(`${key} = ?`);
//         queries.push(`\`${key}\` = ?`);
//         values.push(value);
//     }

//     // If there is a new image, handle the upload to S3 and include in the update
//     if (req.file) {
//         // ... [your existing logic to handle file upload]
//         // make sure to handle the file upload before constructing the query
//         // because the compositeKey will be a part of the update

//         let fileExtension;
//         switch (req.file.mimetype) {
//             case "image/jpeg": fileExtension = "jpeg"; break;
//             case "image/jpg": fileExtension = "jpg"; break;
//             case "image/png": fileExtension = "png"; break;
//             default: return res.status(400).send('Unsupported image type.');
//         }

//         // const compositeKey = `${req.file.originalname}.${fileExtension}`;
//         const compositeKey = `${key}.${fileExtension}`;
//         //const compositeKey = `${key}`;
//         await uploadlogoS3(req.file.buffer, organisation, compositeKey);


//         // after successfully uploading to S3
//         queries.push(`logo = ?`);
//         values.push(compositeKey);
//     }

//     if (queries.length === 0) {
//         return res.status(400).send('No fields provided for update');
//     }

//     // Finalizing the SQL query
//     let updateSql = `UPDATE organisation SET ${queries.join(', ')} WHERE organisation = ?`;
//     values.push(organisation); // assuming 'organisation' is a unique identifier for the record

//     // Database operation
//     pool.getConnection((err, connection) => {
//         if (err) {
//             console.error("Error getting the connection:", err);
//             return res.status(500).send('Server error');
//         }

//         connection.query(updateSql, values, (err, results) => {
//             connection.release();
//             if (err) {
//                 console.error('Error updating data: ', err);
//                 return res.status(500).send('Error updating data');
//             }
//             res.status(200).send('Data updated successfully');
//         });
//     });
// });
//-----------------end of code--------------------




//---------api for setting status of campaign active/inactive----------
app.post('/setStatus', (req, res) => {
    const { status_value, campaignname } = req.body;
    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }
        let updateSQL = 'UPDATE campaign_table SET status = ? WHERE campaign_name = ?';
        connection.query(updateSQL, [status_value, campaignname], (err, result) => {
            connection.release();
            if (err) {
                console.error('Error updating data: ', err);
                return res.status(500).send('Error updating data');
            }
            res.status(200).send('Data updated successfully');

        });
    });
});
//--------end of code---------------------------



//---------api for getting the campaignlist based on organisation + all the users emailid with campaignid---------
/* app.get('/organisation/:name', (req, res) => {
    const { name } = req.params;

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).send('server error');
        }

        let sql = 'SELECT campaign_name,campaignid,DATE_FORMAT(startdate, "%Y-%m-%d") AS startdate,DATE_FORMAT(enddate, "%Y-%m-%d") AS enddate,status FROM campaign_table WHERE organisation = ?';

        connection.query(sql, [name], async (err, campaigns) => {
            if (err) {
                connection.release();
                return res.status(500).send('error fetching data');
            }

            const promises = campaigns.map(async (campaign) => {
                const sqlEmails = 'SELECT emailid FROM campaign_users WHERE campaignid = ?';
                const [emailResults] = await connection.promise().query(sqlEmails, [campaign.campaignid]);
                campaign.emails = emailResults.map(result => result.emailid);
                return campaign;
            });

            Promise.all(promises).then((resultsWithEmails) => {
                connection.release();
                res.status(200).send(resultsWithEmails);
            }).catch((err) => {
                connection.release();
                return res.status(500).send('error fetching associated emails');
            });
        });
    });
});
//-----------------end of code----------------------
 */



//---------api for getting the campaignlist based on organisation + all the users emailid with campaignid+usertype---------
app.get('/organisation/:name', (req, res) => {
    const { name } = req.params;

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).send('server error');
        }

        let sql = 'SELECT campaign_name, campaignid, scantype, `desc`, DATE_FORMAT(startdate, "%Y-%m-%d") AS startdate, DATE_FORMAT(enddate, "%Y-%m-%d") AS enddate, status FROM campaign_table WHERE organisation = ?';

        connection.query(sql, [name], async (err, campaigns) => {
            if (err) {
                connection.release();
                return res.status(500).send('error fetching data');
            }

            const promises = campaigns.map(async (campaign) => {
                const sqlEmailsAndUserTypes = `
                    SELECT cu.emailid, cms.usertype, cms.name
                    FROM campaign_users cu
                    JOIN cmsusers cms ON cu.emailid = cms.emailid
                    WHERE cu.campaignid = ?`;
                const [usersResults] = await connection.promise().query(sqlEmailsAndUserTypes, [campaign.campaignid]);
                campaign.users = usersResults;
                return campaign;
            });

            Promise.all(promises).then((resultsWithUsers) => {
                connection.release();
                res.status(200).send(resultsWithUsers);
            }).catch((err) => {
                connection.release();
                return res.status(500).send('error fetching associated emails and user types');
            });
        });
    });
});
//----------------end of code---------------

//-----api for getting all the campaign details under a specific admin excluding the emailid sent in request---------
// app.get('/campaignsByEmail/:emailid', (req, res) => {
//     const { emailid } = req.params;

//     pool.getConnection((err, connection) => {
//         if (err) {
//             return res.status(500).send('server error');
//         }

//         // First, fetch all campaignid values associated with the provided emailid
//         const sqlCampaignIds = 'SELECT campaignid FROM campaign_users WHERE emailid = ?';

//         connection.query(sqlCampaignIds, [emailid], async (err, campaignsAssociated) => {
//             if (err) {
//                 connection.release();
//                 return res.status(500).send('error fetching associated campaigns');
//             }

//             const campaignIds = campaignsAssociated.map(c => c.campaignid);

//             // For each campaignid, fetch campaign details and associated users
//             const promises = campaignIds.map(async (campaignId) => {
//                 const sqlCampaignDetails = 'SELECT campaign_name, campaignid, DATE_FORMAT(startdate, "%Y-%m-%d") AS startdate, DATE_FORMAT(enddate, "%Y-%m-%d") AS enddate FROM campaign_table WHERE campaignid = ?';
//                 const [campaign] = await connection.promise().query(sqlCampaignDetails, [campaignId]);

//                 const sqlAssociatedUsers = 'SELECT cu.emailid, cms.usertype, cms.name FROM campaign_users cu JOIN cmsusers cms ON cu.emailid = cms.emailid WHERE cu.campaignid = ? AND cu.emailid != ?';
//                 const [users] = await connection.promise().query(sqlAssociatedUsers, [campaignId, emailid]);

//                 campaign[0].users = users;
//                 return campaign[0];
//             });

//             Promise.all(promises).then((results) => {
//                 connection.release();
//                 res.status(200).send(results);
//             }).catch((err) => {
//                 connection.release();
//                 return res.status(500).send('error fetching campaign details and associated users');
//             });
//         });
//     });
// });
//-----------------end of code--------------


//-----api for getting all the campaign details under a specific admin including the emailid sent in request
app.get('/campaignsByEmailid/:emailid', (req, res) => {
    const { emailid } = req.params;

    pool.getConnection((err, connection) => {
        if (err) {
            return res.status(500).send('server error');
        }

        // First, fetch all campaignid values associated with the provided emailid
        const sqlCampaignIds = 'SELECT campaignid FROM campaign_users WHERE emailid = ?';

        connection.query(sqlCampaignIds, [emailid], async (err, campaignsAssociated) => {
            if (err) {
                connection.release();
                return res.status(500).send('error fetching associated campaigns');
            }

            const campaignIds = campaignsAssociated.map(c => c.campaignid);

            // For each campaignid, fetch campaign details and associated users
            const promises = campaignIds.map(async (campaignId) => {
                const sqlCampaignDetails = 'SELECT campaign_name, campaignid, scantype, status, `desc`, DATE_FORMAT(startdate, "%Y-%m-%d") AS startdate, DATE_FORMAT(enddate, "%Y-%m-%d") AS enddate FROM campaign_table WHERE campaignid = ?';
                const [campaign] = await connection.promise().query(sqlCampaignDetails, [campaignId]);

                const sqlAssociatedUsers = 'SELECT cu.emailid, cms.usertype, cms.name FROM campaign_users cu JOIN cmsusers cms ON cu.emailid = cms.emailid WHERE cu.campaignid = ?';
                const [users] = await connection.promise().query(sqlAssociatedUsers, [campaignId]);

                campaign[0].users = users;
                return campaign[0];
            });

            Promise.all(promises).then((results) => {
                connection.release();
                res.status(200).send(results);
            }).catch((err) => {
                connection.release();
                return res.status(500).send('error fetching campaign details and associated users');
            });
        });
    });
});
//-----------------end of code-------------------------------    



//-----new api for creating campaignid and sending in response---------------------- 
app.get('/nextCampaignId', (req, res) => {

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        let sql = 'SELECT MAX(campaignid) AS max_id FROM campaign_table';
        connection.query(sql, (err, results) => {
            connection.release();
            if (err) {
                console.log(err);
                return res.status(500).json({ error: err });
            } else {
                const campaignid = results[0].max_id + 1;
                return res.status(200).json({ CampaignId: campaignid });
            }
        });
    });
});
//------------end of code--------------------


//-------- new api for creating campaign with all the details without usertype and emailid of user/admin----------------
// app.post('/createNewCampaign', (req, res) => {
//     const { campaignid, organisation, campaignname, startdate, enddate, desc, scantype } = req.body;

//     if (!campaignid || !organisation || !campaignname || !startdate || !enddate || !desc) {
//         return res.status(400).json({ message: 'incomplete details' });
//     }

//     pool.getConnection((err, connection) => {
//         if (err) {
//             console.error("Error getting the connection:", err);
//             return res.status(500).send('Server error');
//         }

//         const status = 'inactive';
//         let sql = 'INSERT INTO campaign_table(campaignid, organisation, campaign_name, startdate, enddate, `desc`, status, scantype) VALUES(?,?,?,?,?,?,?,?)';
//         connection.query(sql, [campaignid, organisation, campaignname, startdate, enddate, desc, status, scantype], (err, results) => {
//             connection.release();
//             if (err) {
//                 console.log(err);
//                 return res.status(500).json({ error: err });
//             } else {
//                 return res.status(200).json({ message: 'Campaign created successfully' });
//             }
//         });
//     });
// });
//--------------------end of code----------------------------

//--api for getting the users list(name,emailid,usertype,and the campaigns they are associated with) based on organisation name----
app.get('/users_by_organisation/:organisation', (req, res) => {
    const organisation = req.params.organisation;

    const query = `
        SELECT 
            u.name, 
            u.emailid, 
            u.usertype,
            c.campaignid,
            c.campaign_name
        FROM 
            cmsusers u
        JOIN 
            campaign_users uc ON u.emailid = uc.emailid
        JOIN 
            campaign_table c ON uc.campaignid = c.campaignid
        WHERE 
            c.organisation = ?
    `;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        connection.query(query, [organisation], (err, results) => {
            connection.release();
            if (err) {
                res.status(500).send({ error: 'Database error.' });
                return;
            }

            const users = {};
            results.forEach(row => {
                const email = row.emailid;
                if (!users[email]) {
                    users[email] = {
                        name: row.name,
                        emailid: email,
                        usertype: row.usertype,
                        campaigns: []
                    };
                }
                users[email].campaigns.push({
                    campaignid: row.campaignid,
                    campaign_name: row.campaign_name
                });
            });

            res.send(Object.values(users));
        });
    });
});
//------------end of code-----------------



//--------api for editing created campaigns(startdate/enddate/user&admins)----------------
app.post('/editCampaign', (req, res) => {
    const { startdate, enddate, desc, campaign_name, newcampaign_name } = req.body;

    if (!campaign_name) {
        return res.status(400).json({ error: "Campaign name is required to update." });
    }

    // Start constructing the query
    let updateFields = [];
    let queryParams = [];

    if (startdate) {
        updateFields.push('startdate = ?');
        queryParams.push(startdate);
    }

    if (enddate) {
        updateFields.push('enddate = ?');
        queryParams.push(enddate);
    }

    if (desc) {
        updateFields.push('`desc` = ?');
        queryParams.push(desc);
    }

    if (newcampaign_name) {
        updateFields.push('campaign_name = ?');
        queryParams.push(newcampaign_name);
    }

    if (updateFields.length === 0) {
        return res.status(400).json({ message: 'No fields provided for update' });
    }

    queryParams.push(campaign_name);
    let sql = `UPDATE campaign_table SET ${updateFields.join(', ')} WHERE campaign_name = ?`;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        connection.query(sql, queryParams, (err, results) => {
            connection.release();
            if (err) {
                console.log(err);
                return res.status(500).json({ error: err });
            } else {
                return res.status(200).json({ message: 'Campaign updated successfully' });
            }
        });
    });
});
//--------------------end of code----------------------------


//---------api for deleting the campaigns by campaign_name---------------
app.delete('/deleteCampaign/:campaign_name', (req, res) => {
    const { campaign_name } = req.params;

    if (!campaign_name) {
        return res.status(400).json({ message: 'campaign_name is required' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        const sqlFetchCampaignId = 'SELECT campaignid FROM campaign_table WHERE campaign_name = ?';
        connection.query(sqlFetchCampaignId, [campaign_name], async (err, results) => {

            if (err || results.length === 0) {
                connection.release();
                return res.status(500).json({ message: 'Error fetching campaign or campaign not found: ' + err });
            }

            const campaignId = results[0].campaignid;

            // Start a transaction to ensure all deletions are successful
            connection.beginTransaction(err => {
                if (err) {
                    connection.release();
                    return res.status(500).json({ message: 'Error starting transaction: ' + err });
                }

                const deleteFromCampaignConfig = 'DELETE FROM campaign_config WHERE campaignid = ?';
                connection.query(deleteFromCampaignConfig, [campaignId], (err, _results) => {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            res.status(500).json({ message: 'Error deleting from campaign_config: ' + err });
                        });
                    }

                    const deleteFromCampaignUsers = 'DELETE FROM campaign_users WHERE campaignid = ?';
                    connection.query(deleteFromCampaignUsers, [campaignId], (err, _results) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                res.status(500).json({ message: 'Error deleting from campaign_users: ' + err });
                            });
                        }

                        const deleteFromCampaignTable = 'DELETE FROM campaign_table WHERE campaignid = ?';
                        connection.query(deleteFromCampaignTable, [campaignId], (err, _results) => {
                            if (err) {
                                return connection.rollback(() => {
                                    connection.release();
                                    res.status(500).json({ message: 'Error deleting from campaign_table: ' + err });
                                });
                            }

                            connection.commit(async (err) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        res.status(500).json({ message: 'Error committing transaction: ' + err });
                                    });
                                }
                                connection.release();  // Release DB connection

                                // Now proceed with S3 deletion
                                // const bucketName = 'your-s3-bucket-name'; // replace with your actual bucket name
                                const folderName = campaignId.toString();

                                try {
                                    // List objects in the folder
                                    const params = {
                                        Bucket: bucketName,
                                        Prefix: folderName + '/'
                                    };

                                    const listedObjects = await S3.listObjectsV2(params).promise();

                                    if (listedObjects.Contents.length === 0) return;

                                    // Objects need to be deleted individually
                                    const deleteParams = {
                                        Bucket: bucketName,
                                        Delete: { Objects: [] }
                                    };

                                    listedObjects.Contents.forEach(({ Key }) => {
                                        deleteParams.Delete.Objects.push({ Key });
                                    });

                                    await S3.deleteObjects(deleteParams).promise();

                                    if (listedObjects.IsTruncated) {
                                        // Repeat the process if the list is incomplete due to truncation
                                    }
                                } catch (S3Err) {
                                    console.error(S3Err);
                                    return res.status(500).json({ message: 'Error deleting campaign folder from S3: ' + S3Err });
                                }

                                // Send final response
                                res.status(200).json({ message: 'Campaign and associated entries deleted successfully' });
                            });
                        });
                    });
                });
            });
        });
    });
});
//---------------end of code------------------



//-----------api for editing user/admin---------
app.post('/editUserDetails', async (req, res) => {
    const { name, password, usertype, oldemailid, newemailid } = req.body;

    let updateFields = [];
    let queryParams = [];

    if (name) {
        updateFields.push('name = ?');
        queryParams.push(name);
    }

    if (password) {
        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            updateFields.push('password = ?');
            queryParams.push(hashedPassword);
        } catch (err) {
            console.error(err);
            return res.status(500).json({ message: 'Error hashing password: ' + err });
        }
    }

    if (usertype) {
        updateFields.push('usertype = ?');
        queryParams.push(usertype);
    }

    if (newemailid) {
        updateFields.push('emailid = ?');
        queryParams.push(newemailid);
    }

    if (updateFields.length === 0) {
        return res.status(400).json({ message: 'No fields provided for update' });
    }

    queryParams.push(oldemailid);
    let sql = `UPDATE cmsusers SET ${updateFields.join(', ')} WHERE emailid = ?`;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        connection.query(sql, queryParams, (err, results) => {
            if (err) {
                console.log(err);
                connection.release();
                return res.status(500).json({ error: err });
            } else {
                // If there's a new email to be updated, update the campaign_users table as well.
                if (newemailid) {
                    let updateCampaignUsersSQL = `UPDATE campaign_users SET emailid = ? WHERE emailid = ?`;
                    connection.query(updateCampaignUsersSQL, [newemailid, oldemailid], (err, campaignUpdateResults) => {
                        connection.release();  // release connection
                        if (err) {
                            console.log(err);
                            return res.status(500).json({ error: err });
                        } else {
                            return res.status(200).json({ message: 'Data updated successfully in both tables' });
                        }
                    });
                } else {
                    connection.release();  // release connection if there's no new email to update
                    return res.status(200).json({ message: 'Data updated successfully in cmsusers table' });
                }
            }
        });
    });
});
//------------------end of code-------------------



//----api for editing organisation------
app.post('/editOrganisation', (req, res) => {
    const { organisation, neworganisation, desc } = req.body;

    // Validate input: at least one target update field should be provided.
    if (!organisation || (!neworganisation && !desc)) {
        return res.status(400).json({ message: 'Insufficient data to process the request' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                return res.status(500).json({ message: 'Error starting transaction: ' + err });
            }

            // A helper function to execute SQL queries and handle any potential errors
            function executeQuery(query, queryParams, errorMessage, callback) {
                connection.query(query, queryParams, (err, _results) => {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            res.status(500).json({ message: errorMessage + err });
                        });
                    }
                    callback();
                });
            }

            // Construct the update query based on the provided data
            let updateOrganisationQuery = 'UPDATE organisation SET';
            const updateValues = [];
            const queryParams = [];

            if (neworganisation) {
                updateValues.push(' organisation = ?');
                queryParams.push(neworganisation);
            }
            if (desc) {
                updateValues.push(' `desc` = ?');
                queryParams.push(desc);
            }

            // Joining all updates and adding the WHERE condition
            updateOrganisationQuery += updateValues.join(',') + ' WHERE organisation = ?';
            queryParams.push(organisation);

            // Execute the organisation table update
            executeQuery(
                updateOrganisationQuery,
                queryParams,
                'Error updating organisation table: ',
                () => {
                    // Check if we need to update the organisation in other tables as well
                    if (neworganisation) {
                        // Update campaign_table
                        executeQuery(
                            'UPDATE campaign_table SET organisation = ? WHERE organisation = ?',
                            [neworganisation, organisation],
                            'Error updating campaign_table: ',
                            () => {
                                // Update cmsusers table
                                executeQuery(
                                    'UPDATE cmsusers SET organisation = ? WHERE organisation = ?',
                                    [neworganisation, organisation],
                                    'Error updating cmsusers table: ',
                                    () => {
                                        // All updates successful, commit the transaction
                                        connection.commit((err) => {
                                            if (err) {
                                                return connection.rollback(() => {
                                                    connection.release();
                                                    res.status(500).json({ message: 'Error committing transaction: ' + err });
                                                });
                                            }
                                            connection.release();
                                            res.status(200).json({ message: 'Organisation updated successfully.' });
                                        });
                                    }
                                );
                            }
                        );
                    } else {
                        // If only the organisation table was updated, we can commit the transaction
                        connection.commit((err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    connection.release();
                                    res.status(500).json({ message: 'Error committing transaction: ' + err });
                                });
                            }
                            connection.release();
                            res.status(200).json({ message: 'Organisation description updated successfully.' });
                        });
                    }
                }
            );
        });
    });
});
//-------------end of code---------------


//-----assign multiple campaigns to user/admin-----------
app.post('/assignCampaignToUser', (req, res) => {
    const { emailid, campaign_name } = req.body;

    if (!emailid || !campaign_name) {
        return res.status(400).send('please provide complete details');
    }

    let querySql = 'SELECT campaignid FROM campaign_table WHERE campaign_name = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting the connection: ', err);
            return res.status(500).send('Server Error');
        }
        connection.query(querySql, [campaign_name], (err, response) => {
            connection.release();
            if (err) {
                return res.status(400).send('Error getting the campaignid: ' + err);
            }

            const campaignid = response[0].campaignid;

            let insertSql = 'INSERT INTO campaign_users(emailid,campaignid) VALUES(?,?)';

            connection.query(insertSql, [emailid, campaignid], (err, response) => {
                connection.release();
                if (err) {
                    return res.status(400).send('Error inserting the data: ' + err);
                }
                res.status(200).send('New campaign assigned to the user');
            });

        });
    });
});
//-------------end of code-----------------


//-----api for removing campaign from user/admin--------
app.delete('/removeCampaignFromUser', (req, res) => {
    const { emailid, campaign_name } = req.body;

    if (!emailid || !campaign_name) {
        return res.status(400).send('please provide complete details');
    }

    let querySql = 'SELECT campaignid FROM campaign_table WHERE campaign_name = ?';

    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error getting the connection: ', err);
            return res.status(500).send('Server Error');
        }
        connection.query(querySql, [campaign_name], (err, response) => {
            connection.release();
            if (err) {
                return res.status(400).send('Error getting the campaignid: ' + err);
            }

            const campaignid = response[0].campaignid;

            let checkSql = 'SELECT * FROM campaign_users WHERE emailid = ? AND campaignid = ? ';

            connection.query(checkSql, [emailid, campaignid], (err, responses) => {
                connection.release();
                if (err) {
                    return res.status(400).send('Error fetching the data: ' + err);
                }
                if (responses.length === 0) {
                    return res.status(400).send('user is not associated with the campaign');
                }
                // res.status(200).send('New campaign assigned to the user');

                let deleteSql = 'DELETE FROM campaign_users WHERE emailid = ? AND campaignid = ?';
                connection.query(deleteSql, [emailid, campaignid], (err, response) => {
                    connection.release();
                    if (err) {
                        return res.status(400).send('Error deleting the data: ' + err);
                    }
                    res.status(200).send('campaign deleted from user');
                });
            });

        });
    });
});
//---------end of code-----------


//------api for deleteing the organisation and all its related data across all tables and S3 bucket-------
app.delete('/deleteOrganizationData/:organization_name', (req, res) => {
    const organization = req.params.organization_name;

    if (!organization) {
        return res.status(400).send('Organization name is required');
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                return res.status(500).send('Error starting transaction');
            }

            const sqlFetchCampaignIds = 'SELECT campaignid FROM campaign_table WHERE organisation = ?';
            connection.query(sqlFetchCampaignIds, [organization], (err, campaigns) => {
                if (err) {
                    connection.release();
                    return res.status(500).send('Error fetching campaign IDs: ' + err.message);
                }

                const campaignIds = campaigns.map(campaign => campaign.campaignid);
                const hasCampaigns = campaignIds.length > 0;

                const conditionalQueries = [];
                conditionalQueries.push({ sql: 'DELETE FROM organisation WHERE organisation = ?', values: [organization] });

                if (hasCampaigns) {
                    const campaignIdPlaceholder = campaignIds.join(',');
                    conditionalQueries.push({ sql: `DELETE FROM campaign_table WHERE campaignid IN (${campaignIdPlaceholder})` });
                    conditionalQueries.push({ sql: `DELETE FROM campaign_config WHERE campaignid IN (${campaignIdPlaceholder})` });
                    conditionalQueries.push({ sql: `DELETE FROM custdata WHERE campaignid IN (${campaignIdPlaceholder})` });
                    conditionalQueries.push({ sql: `DELETE FROM campaign_users WHERE campaignid IN (${campaignIdPlaceholder})` });
                }

                conditionalQueries.push({ sql: 'DELETE FROM cmsusers WHERE organisation = ?', values: [organization] });

                let queryIndex = 0;

                const executeQuery = () => {
                    if (queryIndex >= conditionalQueries.length) {
                        if (hasCampaigns) {
                            deleteFromS3(campaignIds, (s3Error) => {
                                if (s3Error) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        return res.status(500).send('Error deleting files from S3: ' + s3Error.message);
                                    });
                                }
                                finishTransaction();
                            });
                        } else {
                            finishTransaction();
                        }
                        return;
                    }

                    const query = conditionalQueries[queryIndex];
                    connection.query(query.sql, query.values, (err, result) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(500).send('Error occurred during transaction: ' + err.message);
                            });
                        }
                        queryIndex++;
                        executeQuery();
                    });
                };

                const deleteFromS3 = (campaignIds, callback) => {
                    let completedDeletions = 0;
                    let deletionError = null;

                    campaignIds.forEach(campaignId => {
                        const s3DeleteParams = {
                            Bucket: bucketName,
                            Prefix: campaignId + '/' // assuming the campaignId is used as the folder name in S3
                        };

                        S3.listObjectsV2(s3DeleteParams, function (listErr, listData) {
                            if (listErr) {
                                deletionError = listErr;
                                return;
                            }

                            const objectsToDelete = listData.Contents.map(content => ({ Key: content.Key }));

                            if (objectsToDelete.length === 0) {
                                completedDeletions++;
                                if (completedDeletions === campaignIds.length) {
                                    return callback(deletionError);
                                }
                                return;
                            }

                            S3.deleteObjects({
                                Bucket: bucketName,
                                Delete: { Objects: objectsToDelete }
                            }, function (deleteErr, deleteData) {
                                if (deleteErr) {
                                    deletionError = deleteErr;
                                }
                                completedDeletions++;
                                if (completedDeletions === campaignIds.length) {
                                    return callback(deletionError);
                                }
                            });
                        });
                    });
                };

                const finishTransaction = () => {
                    connection.commit(err => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                return res.status(500).send('Transaction commit error: ' + err.message);
                            });
                        }
                        connection.release();
                        return res.status(200).send('Data deletion completed successfully.');
                    });
                };

                executeQuery(); // Start the deletion process.
            });
        });
    });
});
//---------end of code code in production-------------


//-----api for adding player details (phonenumber,name,emailid,campaignid)---------
app.post('/addPlayerDetails', (req, res) => {
    const currentMoment = moment().tz('Asia/Kolkata');
    const date = currentMoment.format('YYYY-MM-DD HH:mm:ss');
    const phonenumber = req.body.phonenumber;
    const name = req.body.name;
    const emailid = req.body.emailid; // This may or may not be provided
    const campaignid = req.body.campaignid;

    if (!phonenumber || !name || !campaignid) {
        return res.status(400).json({ message: 'Incomplete details' });
    }

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        const getCampaignName = 'SELECT campaign_name, organisation FROM campaign_table WHERE campaignid = ?';
        connection.query(getCampaignName, [campaignid], (err, results) => {
            if (err) {
                connection.release();
                console.error(err);
                return res.status(500).json({ message: 'Error fetching the data: ' + err });
            }

            // If results are returned, meaning the campaign exists
            if (results && results.length > 0) {
                const campaign_name = results[0].campaign_name;
                const organisation = results[0].organisation;

                // Prepare the insert statement with optional email
                let insertColumns = 'phonenumber, name, campaignid, date, campaign_name, organisation';
                let queryPlaceholders = '?, ?, ?, ?, ?, ?';
                let queryValues = [phonenumber, name, campaignid, date, campaign_name, organisation];

                // If emailid is provided, append it to the SQL query
                if (emailid) {
                    insertColumns += ', emailid';
                    queryPlaceholders += ', ?';
                    queryValues.push(emailid);
                }

                let insertSql = `INSERT INTO custdata (${insertColumns}) VALUES (${queryPlaceholders})`;
                connection.query(insertSql, queryValues, (err, results) => {
                    connection.release();
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Error inserting the data: ' + err });
                    }
                    return res.status(200).send('Player data inserted successfully.');
                });
            } else {
                connection.release();
                // If campaign_name and organisation don't exist, throw an error
                return res.status(404).json({ message: `No organisation and campaign found for the given campaign ID: ${campaignid}` });
            }
        });
    });
});
//--------end of code------------------






//------api for deleteing the organisation and all its related data across all tables and S3 bucket-------
// app.delete('/deleteOrganizationData/:organization_name', (req, res) => {
//   const organization = req.params.organization_name;

//   if (!organization) {
//     return res.status(400).send('Organization name is required');
//   }

//   pool.getConnection((err, connection) => {
//     if (err) {
//       console.error("Error getting the connection:", err);
//       return res.status(500).send('Server error');
//     }

//     connection.beginTransaction(err => {
//       if (err) {
//         connection.release();
//         return res.status(500).send('Error starting transaction');
//       }

//       const sqlFetchCampaignIds = 'SELECT campaignid FROM campaign_table WHERE organisation = ?';
//       connection.query(sqlFetchCampaignIds, [organization], (err, campaigns) => {
//         if (err) {
//           connection.release();
//           return res.status(500).send('Error fetching campaign IDs: ' + err.message);
//         }

//         const campaignIds = campaigns.map(campaign => campaign.campaignid);
//         const hasCampaigns = campaignIds.length > 0;

//         const conditionalQueries = [];
//         conditionalQueries.push({ sql: 'DELETE FROM organisation WHERE organisation = ?', values: [organization] });

//         if (hasCampaigns) {
//           const campaignIdPlaceholder = campaignIds.join(',');
//           conditionalQueries.push({ sql: `DELETE FROM campaign_table WHERE campaignid IN (${campaignIdPlaceholder})` });
//           conditionalQueries.push({ sql: `DELETE FROM campaign_config WHERE campaignid IN (${campaignIdPlaceholder})` });
//           conditionalQueries.push({ sql: `DELETE FROM custdata WHERE campaignid IN (${campaignIdPlaceholder})` });
//           conditionalQueries.push({ sql: `DELETE FROM campaign_users WHERE campaignid IN (${campaignIdPlaceholder})` });
//         }

//         conditionalQueries.push({ sql: 'DELETE FROM cmsusers WHERE organisation = ?', values: [organization] });

//         let queryIndex = 0;

//         const executeQuery = () => {
//           if (queryIndex >= conditionalQueries.length) {
//             if (hasCampaigns) {
//               deleteFromS3(campaignIds, (s3Error) => {
//                 if (s3Error) {
//                   return connection.rollback(() => {
//                     connection.release();
//                     return res.status(500).send('Error deleting files from S3: ' + s3Error.message);
//                   });
//                 }
//                 finishTransaction();
//               });
//             } else {
//               finishTransaction();
//             }
//             return;
//           }

//           const query = conditionalQueries[queryIndex];
//           connection.query(query.sql, query.values, (err, result) => {
//             if (err) {
//               return connection.rollback(() => {
//                 connection.release();
//                 return res.status(500).send('Error occurred during transaction: ' + err.message);
//               });
//             }
//             queryIndex++;
//             executeQuery();
//           });
//         };

//         const deleteFromS3 = (campaignIds, callback) => {
//           let completedDeletions = 0;
//           let deletionError = null;

//           campaignIds.forEach(campaignId => {
//             const s3DeleteParams = {
//               Bucket: bucketName,
//               Prefix: campaignId + '/' // assuming the campaignId is used as the folder name in S3
//             };

//             S3.listObjectsV2(s3DeleteParams, function (listErr, listData) {
//               if (listErr) {
//                 deletionError = listErr;
//                 return;
//               }

//               const objectsToDelete = listData.Contents.map(content => ({ Key: content.Key }));

//               if (objectsToDelete.length === 0) {
//                 completedDeletions++;
//                 if (completedDeletions === campaignIds.length) {
//                   return callback(deletionError);
//                 }
//                 return;
//               }

//               S3.deleteObjects({
//                 Bucket: bucketName,
//                 Delete: { Objects: objectsToDelete }
//               }, function (deleteErr, deleteData) {
//                 if (deleteErr) {
//                   deletionError = deleteErr;
//                 }
//                 completedDeletions++;
//                 if (completedDeletions === campaignIds.length) {
//                   return callback(deletionError);
//                 }
//               });
//             });
//           });
//         };

//         const finishTransaction = () => {
//           connection.commit(err => {
//             if (err) {
//               return connection.rollback(() => {
//                 connection.release();
//                 return res.status(500).send('Transaction commit error: ' + err.message);
//               });
//             }
//             connection.release();
//             return res.status(200).send('Data deletion completed successfully.');
//           });
//         };

//         executeQuery(); // Start the deletion process.
//       });
//     });
//   });
// });
//---------end of code code in production-------------




//----------api for getting all the signedurls orderby pageno without checking the status,enddate,startdate---------------------- 
app.get('/withoutStatus/allsignedurls/:campaignid/:scantype', async (req, res) => {
    try {
        const { campaignid, scantype } = req.params;
        // const currentMoment = moment().tz('Asia/Kolkata');
        // const currentDate = currentMoment.format('YYYY-MM-DD');
        // const currentDate = currentMoment;

        // const results = await checkCampaignStatus(campaignid);

        // const startDate = moment(results[0].formatted_startdate, "YYYY-MM-DD");
        // const endDate = moment(results[0].formatted_enddate, 'YYYY-MM-DD').endOf('day');

        // if (results[0].status === 'inactive' || !currentDate.isBetween(startDate, endDate, undefined, '[]')) {
        //     return res.status(400).send('Cannot launch campaign');
        // }

        let keysData;

        if (scantype === 'imagescan') {
            keysData = await fetchKeysFromDB2(campaignid);
        } else if (scantype === 'QRscan') {
            keysData = await fetchKeysFromDB1(campaignid, scantype);
        } else {
            return res.status(400).send('Invalid scantype provided.');
        }

        const signedURLs = await Promise.all(keysData.map(data => getPresignedUrl(campaignid, data.pageno, data.key)));
        const response = keysData.map((data, index) => ({ pageno: data.pageno, key: data.key, value: signedURLs[index] }));
        // const response = keysData.map((data, index) => ({ pageno: data.pageno,  value: signedURLs[index] }));
        // Group by page number
        const groupedResponse = response.reduce((accumulator, current) => {
            (accumulator[current.pageno] = accumulator[current.pageno] || []).push({ key: current.key, value: current.value });
            return accumulator;                                                 // ({ [current.key] : current.value })
        }, {});

        res.status(200).send(groupedResponse);

    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Failed to generate the signed URLs.');
    }
});

// async function checkCampaignStatus(campaignid) {
//     return new Promise((resolve, reject) => {
//         pool.getConnection((err, connection) => {
//             if (err) {
//                 reject('Error getting the connection: ' + err);
//             } else {
//                 const checksql = 'SELECT DATE_FORMAT(startdate, "%Y-%m-%d") AS formatted_startdate,DATE_FORMAT(enddate, "%Y-%m-%d") AS formatted_enddate, status FROM campaign_table WHERE campaignid = ?';
//                 connection.query(checksql, [campaignid], (err, results) => {
//                     connection.release();
//                     if (err) {
//                         reject('Error querying the database: ' + err);
//                     } else {
//                         resolve(results);
//                     }
//                 });
//             }
//         });
//     });
// }


function fetchKeysFromDB2(campaignid) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ?";
            connection.query(sql, [campaignid], (err, results) => {
                connection.release();
                if (err) {
                    reject(err);
                } else {
                    resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
                }
            });
        });
    });
}

function fetchKeysFromDB1(campaignid, scantype) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                return res.status(500).send('Server error');
            }
            const sql = "SELECT `key`, `pageno` FROM campaign_config WHERE campaignid = ? AND scantype = ?";
            connection.query(sql, [campaignid, scantype], (err, results) => {
                connection.release();
                if (err) {
                    reject(err);
                } else {
                    resolve(results.map(row => ({ key: row.key, pageno: row.pageno })));
                }
            });
        });
    });

}

function getPresignedUrl(campaignid, pageno, key) {
    return new Promise((resolve, reject) => {
        const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${key}`,
            Expires: 3600  // URL will be valid for 1 hour
        };

        S3.getSignedUrl('getObject', params, (err, url) => {
            if (err) {
                reject(err);
            } else {
                resolve(url);
            }
        });
    });
}
//---------------------end of code------------------



//-------- new api for creating campaign with all the details(usertype and emailid) as per latest requirements----------------
app.post('/api/createNewCampaign', (req, res) => {
    const { campaignid, organisation, campaignname, startdate, enddate, desc, scantype, usertype, emailid } = req.body;

    if (!campaignid || !organisation || !campaignname || !startdate || !enddate || !desc || !usertype || !emailid) {
        return res.status(400).json({ message: 'incomplete details' });
    }

    // if(usertype == 'superadmin')

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        if (usertype == 'superadmin') {

            const status = 'inactive';
            let sql = 'INSERT INTO campaign_table(campaignid, organisation, campaign_name, startdate, enddate, `desc`, status, scantype) VALUES(?,?,?,?,?,?,?,?)';
            connection.query(sql, [campaignid, organisation, campaignname, startdate, enddate, desc, status, scantype], (err, results) => {
                connection.release();
                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: err });
                } else {
                    return res.status(200).json({ message: 'Campaign created successfully' });
                }
            });
        }

        if (usertype == 'admin' || usertype == 'user') {
            connection.beginTransaction(err => {
                if (err) {
                    connection.release();
                    return res.status(500).json({ message: 'Error starting transaction: ' + err });
                }

                const status = 'inactive';
                let sql = 'INSERT INTO campaign_table(campaignid, organisation, campaign_name, startdate, enddate, `desc`, status, scantype) VALUES(?,?,?,?,?,?,?,?)';
                connection.query(sql, [campaignid, organisation, campaignname, startdate, enddate, desc, status, scantype], (err, results) => {

                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            res.status(500).json({ message: 'Error inserting the data into campaign_table : ' + err })
                        });
                    }
                    // return res.status(200).json({ message: 'Campaign created successfully' });
                    let insertSql = 'INSERT INTO campaign_users (emailid, campaignid) VALUES(?,?)';
                    connection.query(insertSql, [emailid, campaignid], (err, results) => {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                res.status(500).json({ message: 'Error inserting data into campaign_users: ' + err });
                            });
                        }
                        connection.commit(async (err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    connection.release();
                                    res.status(500).json({ message: 'Error committing transaction: ' + err });
                                });
                            }
                            connection.release();
                            return res.status(200).json({ message: 'Campaign created successfully' });
                        });

                    });

                });

            });

        }

    });
});
//--------------------end of code----------------------------



//--api for getting the users list(name,emailid,usertype,and the campaigns they are associated with & empty if they are not associated with any campaign) based on organisation name----
app.get('/api/users_by_organisation/:organisation', (req, res) => {
    const organisation = req.params.organisation;

    const query = `
        SELECT 
            u.name, 
            u.emailid, 
            u.usertype,
            c.campaignid,
            c.campaign_name
        FROM 
            cmsusers u
        LEFT JOIN 
            campaign_users uc ON u.emailid = uc.emailid
        LEFT JOIN 
            campaign_table c ON uc.campaignid = c.campaignid AND c.organisation = ?
        WHERE 
            u.organisation = ?
    `;

    pool.getConnection((err, connection) => {
        if (err) {
            console.error("Error getting the connection:", err);
            return res.status(500).send('Server error');
        }

        connection.query(query, [organisation, organisation], (err, results) => {
            connection.release();
            
            if (err) {
                console.error("Error querying the database:", err);
                res.status(500).send({ error: 'Database error.' });
                return;
            }

            const users = {};
            results.forEach(row => {
                const email = row.emailid;
                if (!users[email]) {
                    users[email] = {
                        name: row.name,
                        emailid: email,
                        usertype: row.usertype,
                        campaigns: []
                    };
                }
                if (row.campaignid && row.campaign_name) {
                    users[email].campaigns.push({
                        campaignid: row.campaignid,
                        campaign_name: row.campaign_name
                    });
                }
            });

            res.send(Object.values(users));
        });
    });
});
//---------end of code-------------------

//--api for updating image in S3 bucket and checks in database if key already exists-----
app.post("/updateimage/:campaignid/:pageno/:key/:scantype", upload('image').single('image'), async (req, res) => {
    const campaignid = req.params.campaignid;
    const pageno = req.params.pageno;
    const key = req.params.key;
    const scantype = req.params.scantype;

    try {
        if (!req.file) {
            return res.status(400).send({
                msg: "No file provided for upload.",
            });
        }

        // Determine the file extension from mimetype
        let fileExtension;
        switch (req.file.mimetype) {
            case "image/jpeg":
                fileExtension = "jpeg";
                break;
            case "image/jpg":
                fileExtension = "jpg";
                break;
            case "image/png":
                fileExtension = "png";
                break;
            default:
                return res.status(400).send('Unsupported image type.');
        }

        const compositeKey = `${key}.${fileExtension}`;

        // Check if the key exists in the database (without considering the file extension)
        const keyExists = await checkKeyInDB(campaignid, pageno, key);
        if (keyExists) {
            // If key exists, replace the image in S3 and update the database record with the new file extension
            await uploadtoS3(req.file.buffer, campaignid, pageno, compositeKey);
            await updateExistingKeyInDB(campaignid, pageno, key, scantype, fileExtension);
            res.status(200).send('Existing image replaced and database updated with new file extension.');
        } else {
            // If key does not exist, upload the image to S3 and insert a new entry into the database
            await uploadtoS3(req.file.buffer, campaignid, pageno, compositeKey);
            await insertNewKeyInDB(campaignid, pageno, compositeKey, scantype);
            res.status(200).send('Image uploaded and new key stored in database with file extension.');
        }
    } catch (error) {
        console.error("Error while uploading:", error);
        res.status(500).send({
            msg: "Failed to upload the image. Please try again later.",
        });
    }
});

// Function to check if the key exists in the database
const checkKeyInDB = async (campaignid, pageno, key) => {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                reject(err);
            } else {
                // Adjusted the SQL query to check only for the key without the file extension
                const sql = 'SELECT COUNT(*) as count FROM campaign_config WHERE campaignid = ? AND pageno = ? AND `key` LIKE ?';
                connection.query(sql, [campaignid, pageno, key + '%'], (err, result) => {
                    connection.release();
                    if (err) {
                        reject(err);
                    } else {
                        // Resolve true if the key is already in the database
                        resolve(result[0].count > 0);
                    }
                });
            }
        });
    });
};


// Function to update existing key in the database
const updateExistingKeyInDB = (campaignid, pageno, key, scantype, fileExtension) => {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                reject(err);
            } else {
                // Update the key with the new compositeKey including the file extension
                const sql = 'UPDATE campaign_config SET `key` = ?, scantype = ? WHERE campaignid = ? AND pageno = ? AND `key` LIKE ?';
                connection.query(sql, [`${key}.${fileExtension}`, scantype, campaignid, pageno, key + '%'], (err, result) => {
                    connection.release();
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result);
                    }
                });
            }
        });
    });
};


// Function to insert new key in the database
const insertNewKeyInDB = (campaignid, pageno, compositeKey, scantype) => {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) {
                console.error("Error getting the connection:", err);
                reject(err);
            } else {
                const sql = 'INSERT INTO campaign_config (campaignid, pageno, `key`, scantype) VALUES (?, ?, ?, ?)';
                connection.query(sql, [campaignid, pageno, compositeKey, scantype], (err, result) => {
                    connection.release();
                    if (err) {
                        reject(err);
                    } else {
                        resolve(result);
                    }
                });
            }
        });
    });
};


// Function to upload file to S3
const uploadtoS3 = async (fileData, campaignid, pageno, compositeKey) => {
    return new Promise((resolve, reject) => {
        const params = {
            Bucket: bucketName,
            Key: `${campaignid}/${pageno}/${compositeKey}`,
            Body: fileData,
        };
        S3.upload(params, (err, data) => {
            if (err) {
                console.log(err);
                return reject(err);
            }
            console.log(data);
            return resolve(data);
        });
    });
};
//---------end of code----------------------


//---------api for resending the code--------
// app.get('/resendotp/:mobilenumber', (req, res) => {
//     const { mobilenumber } = req.params;
    
// console.log(mobilenumber);
//     if (!mobilenumber) {
//         return res.status(400).send('Mobile number is required.');
//     }
//     //10 digit mobile number will be received in the request
//     const appendmobilenumber = '+91' + mobilenumber;
//     const type = 'text';
//     const resendOtpURL = `https://control.msg91.com/api/v5/otp/retry?mobile=${appendmobilenumber}&retrytype=${type}`;

//     request.post(resendOtpURL, {
//         headers: {
//             'authkey': authKey
//         }
//     }, (error, response, body) => {
//         if (error) {
//             console.error('Error resending OTP:', error);
//             return res.status(500).send('Failed to resend OTP.');
//         }

//         const responseBody = JSON.parse(body);
//         if (responseBody.type === "success") {
//             res.status(200).send('OTP resent successfully.');
//         } else {
//             res.status(400).send(responseBody.message);
//         }
//     });
// });
//-----------end of code-----------





