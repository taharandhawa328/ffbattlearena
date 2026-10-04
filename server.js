require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const multer = require("multer");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const FileType = require("file-type");
const app = express();
const PORT = 3000;
const isProduction =
    process.env.NODE_ENV === "production";
// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);


// ==================================================
// ADMIN SESSIONS
// ==================================================

const adminSessions = new Map();

const ADMIN_SESSION_DURATION =
    8 * 60 * 60 * 1000;


function createAdminSession() {

    const token =
        crypto.randomBytes(32).toString("hex");

    adminSessions.set(token, {
        createdAt: Date.now()
    });

    return token;
}


function getAdminSessionToken(req) {

    const cookies =
        String(req.headers.cookie || "");

    const match =
        cookies.match(
            /(?:^|;\s*)ff_admin_session=([^;]+)/
        );

    return match ? match[1] : null;
}


function requireAdmin(req, res, next) {

    const token =
        getAdminSessionToken(req);

    if (!token) {

        return res.status(401).json({
            success: false,
            message: "Admin authentication required"
        });

    }

    const session =
        adminSessions.get(token);

    if (!session) {

        return res.status(401).json({
            success: false,
            message: "Admin session expired"
        });

    }

    const sessionAge =
        Date.now() - session.createdAt;

    if (
        sessionAge >
        ADMIN_SESSION_DURATION
    ) {

        adminSessions.delete(token);

        return res.status(401).json({
            success: false,
            message: "Admin session expired"
        });

    }

    next();
}
// ==================================================
// SESSION CLEANUP
// ==================================================

setInterval(() => {

    const now =
        Date.now();


    // ------------------------------------------
    // CLEAN ADMIN SESSIONS
    // ------------------------------------------

    for (
        const [token, session]
        of adminSessions
    ) {

        if (
            now - session.createdAt >
            ADMIN_SESSION_DURATION
        ) {

            adminSessions.delete(
                token
            );

        }

    }


    // ------------------------------------------
    // CLEAN CUSTOMER SESSIONS
    // ------------------------------------------

    for (
        const [token, session]
        of userSessions
    ) {

        if (
            now - session.createdAt >
            USER_SESSION_DURATION
        ) {

            userSessions.delete(
                token
            );

        }

    }

}, 60 * 60 * 1000);

// ==================================================
// CUSTOMER SESSIONS
// ==================================================

const userSessions = new Map();

const USER_SESSION_DURATION =
    7 * 24 * 60 * 60 * 1000;


function createUserSession(userId) {

    const token =
        crypto.randomBytes(32).toString("hex");

    userSessions.set(token, {
        userId: userId,
        createdAt: Date.now()
    });

    return token;
}


function getUserSessionToken(req) {

    const cookies =
        String(req.headers.cookie || "");

    const match =
        cookies.match(
            /(?:^|;\s*)ff_user_session=([^;]+)/
        );

    return match ? match[1] : null;
}


function getLoggedInUserId(req) {

    const token =
        getUserSessionToken(req);

    if (!token) {
        return null;
    }

    const session =
        userSessions.get(token);

    if (!session) {
        return null;
    }

    const sessionAge =
        Date.now() - session.createdAt;

    if (
        sessionAge >
        USER_SESSION_DURATION
    ) {

        userSessions.delete(token);

        return null;
    }

    return session.userId;
}


function requireUser(req, res, next) {

    const userId =
        getLoggedInUserId(req);

    if (!userId) {

        return res.status(401).json({
            success: false,
            message: "Customer login required"
        });

    }

    req.userId = userId;

    next();
}
// ==================================================
// SESSION CLEANUP
// ==================================================

setInterval(() => {

    const now = Date.now();

    for (const [token, session] of adminSessions) {

        if (session.expiresAt <= now) {

            adminSessions.delete(token);

        }

    }


    for (const [token, session] of userSessions) {

        if (session.expiresAt <= now) {

            userSessions.delete(token);

        }

    }

}, 60 * 60 * 1000);

// ==================================================
// DATABASE
// ==================================================

const db =
    new Database(
        path.join(
            __dirname,
            "ff-battle-arena.db"
        )
    );
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");
// ==================================================
// DATABASE BACKUP
// ==================================================

const databaseBackupFolder =
    path.join(
        __dirname,
        "database-backups"
    );

if (
    !fs.existsSync(
        databaseBackupFolder
    )
) {
    fs.mkdirSync(
        databaseBackupFolder,
        {
            recursive: true
        }
    );
}

function createDatabaseBackup() {

    try {

        const backupFile =
            path.join(
                databaseBackupFolder,
                "ff-battle-arena-" +
                new Date()
                    .toISOString()
                    .replace(/[:.]/g, "-") +
                ".db"
            );

        db.backup(backupFile)
            .then(() => {

                console.log(
                    "Database backup created:",
                    backupFile
                );

            })
            .catch((error) => {

                console.error(
                    "DATABASE BACKUP ERROR:",
                    error
                );

            });

    } catch (error) {

        console.error(
            "DATABASE BACKUP ERROR:",
            error
        );

    }

}
function cleanupOldDatabaseBackups() {

    try {

        const files = fs.readdirSync(databaseBackupFolder);

        const now = Date.now();

        const thirtyDays =
            30 * 24 * 60 * 60 * 1000;

        files.forEach((file) => {

            if (!file.endsWith(".db")) {
                return;
            }

            const filePath =
                path.join(databaseBackupFolder, file);

            const stats =
                fs.statSync(filePath);

            if (
                now - stats.mtimeMs >
                thirtyDays
            ) {

                fs.unlinkSync(filePath);

                console.log(
                    "Old database backup deleted:",
                    file
                );

            }

        });

    } catch (error) {

        console.error(
            "BACKUP CLEANUP ERROR:",
            error
        );

    }

}
// ==================================================
// PAYMENT PROOF FOLDER
// ==================================================

const paymentProofFolder =
    path.join(
        __dirname,
        "payment-proofs"
    );


if (
    !fs.existsSync(
        paymentProofFolder
    )
) {

    fs.mkdirSync(
        paymentProofFolder,
        {
            recursive: true
        }
    );

}


// ==================================================
// FILE UPLOAD
// ==================================================

const storage =
    multer.diskStorage({

        destination:
            function (
                req,
                file,
                cb
            ) {

                cb(
                    null,
                    paymentProofFolder
                );

            },

        filename:
            function (
                req,
                file,
                cb
            ) {

                const uniqueName =
                    Date.now() +
                    "-" +
                    crypto
                        .randomBytes(8)
                        .toString("hex") +
                    path.extname(
                        file.originalname
                    );

                cb(
                    null,
                    uniqueName
                );

            }

    });


const upload =
    multer({

        storage: storage,

        limits: {
            fileSize:
                5 * 1024 * 1024
        },

        fileFilter:
            function (
                req,
                file,
                cb
            ) {

                if (
                    file.mimetype &&
                    file.mimetype.startsWith(
                        "image/"
                    )
                ) {

                    cb(
                        null,
                        true
                    );

                } else {

                    cb(
                        new Error(
                            "Sirf image files allowed hain."
                        )
                    );

                }

            }

    });


// ==================================================
// MIDDLEWARE
// ==================================================
app.use(helmet());
app.use(
    express.json()
);

app.use(
    express.urlencoded({
        extended: true
    })
);


// ==================================================
// STATIC WEBSITE
// ==================================================

// ==================================================
// SECURE STATIC FILE ACCESS
// ==================================================

app.use((req, res, next) => {

    const blockedFiles = [
        "/ff-battle-arena.db",
        "/ff-battle-arena.db-wal",
        "/ff-battle-arena.db-shm",
        "/server.js"
    ];

    if (
        blockedFiles.includes(req.path) ||
        req.path.startsWith("/payment-proofs/")
        || req.path.startsWith("/database-backups/")
    ) {
        return res.status(404).send("Not Found");
    }

    next();
});
// ==================================================
// PROTECT SENSITIVE FILES
// ==================================================

app.use((req, res, next) => {

    const blockedFiles = [
        "/.env",
        "/package.json",
        "/package-lock.json",
        "/server.js",
        "/ff-battle-arena.db",
        "/ff-battle-arena.db-wal",
        "/ff-battle-arena.db-shm"
    ];

    if (blockedFiles.includes(req.path)) {

        return res.status(403).send(
            "Access denied"
        );

    }

    next();

});
app.use(
    express.static(__dirname)
);


// ==================================================
// USERS TABLE
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE NOT NULL,

        email TEXT UNIQUE NOT NULL,

        password TEXT NOT NULL,

        coins INTEGER NOT NULL DEFAULT 0,

        created_at DATETIME
            DEFAULT CURRENT_TIMESTAMP
    )
`);


// ==================================================
// ROOMS TABLE
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS rooms (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        name TEXT NOT NULL,

        price INTEGER NOT NULL
    )
`);


// ==================================================
// ROOM PURCHASES TABLE
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS room_purchases (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        room_id INTEGER NOT NULL,

        purchased_at DATETIME
            DEFAULT CURRENT_TIMESTAMP
    )
`);


// ==================================================
// COIN PURCHASES TABLE
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS coin_purchases (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        coins INTEGER NOT NULL,

        purchased_at DATETIME
            DEFAULT CURRENT_TIMESTAMP
    )
`);


// ==================================================
// PAYMENT PROOFS TABLE
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS payment_proofs (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        coins INTEGER NOT NULL DEFAULT 0,

        file_name TEXT NOT NULL,

        original_name TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        submitted_at DATETIME
            DEFAULT CURRENT_TIMESTAMP,

        verified_at DATETIME
    )
`);


// ==================================================
// WITHDRAWAL REQUESTS TABLE
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS withdrawal_requests (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        coins INTEGER NOT NULL DEFAULT 0,

        amount INTEGER NOT NULL,

        method TEXT NOT NULL,

        account_name TEXT NOT NULL,

        account_number TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        requested_at DATETIME
            DEFAULT CURRENT_TIMESTAMP,

        processed_at DATETIME
    )
`);
// ==================================================
// ADMIN AUDIT LOGS
// ==================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id INTEGER,
        user_id INTEGER,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);
// ==================================================
// ADMIN AUDIT LOG HELPER
// ==================================================

function createAuditLog(
    action,
    targetType,
    targetId,
    userId,
    details
) {

    try {

        db.prepare(`
            INSERT INTO admin_audit_logs
            (
                action,
                target_type,
                target_id,
                user_id,
                details
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            action,
            targetType,
            targetId || null,
            userId || null,
            details || null
        );

    } catch (error) {

        console.error(
            "AUDIT LOG ERROR:",
            error
        );

    }

}
// ==================================================
// DATABASE MIGRATION
// ==================================================

try {

    db.prepare(`
        ALTER TABLE payment_proofs
        ADD COLUMN coins
        INTEGER NOT NULL DEFAULT 0
    `).run();

} catch (error) {

    // Column already exists

}


try {

    db.prepare(`
        ALTER TABLE payment_proofs
        ADD COLUMN verified_at
        DATETIME
    `).run();

} catch (error) {

    // Column already exists

}

// WITHDRAWAL DATABASE MIGRATION

try {

    db.prepare(`
        ALTER TABLE withdrawal_requests
        ADD COLUMN coins
        INTEGER NOT NULL DEFAULT 0
    `).run();

} catch (error) {

    // Column already exists

}
// ==================================================
// DEFAULT ROOMS
// ==================================================

const roomCount =
    db.prepare(`
        SELECT COUNT(*) AS count
        FROM rooms
    `).get();


if (
    roomCount.count === 0
) {

    const insertRoom =
        db.prepare(`
            INSERT INTO rooms
            (
                name,
                price
            )
            VALUES (?, ?)
        `);

    insertRoom.run(
        "SOLO",
        10
    );

    insertRoom.run(
        "DUO",
        20
    );

    insertRoom.run(
        "SQUAD",
        30
    );

    console.log(
        "Default rooms added."
    );

} else {

    const updateRoom =
        db.prepare(`
            UPDATE rooms
            SET
                name = ?,
                price = ?
            WHERE id = ?
        `);

    updateRoom.run(
        "SOLO",
        10,
        1
    );

    updateRoom.run(
        "DUO",
        20,
        2
    );

    updateRoom.run(
        "SQUAD",
        30,
        3
    );

}


// ==================================================
// SERVER STATUS
// ==================================================

app.get(
    "/api/status",
    function (
        req,
        res
    ) {

        res.json({

            success: true,

            message:
                "FF Battle Arena server is running!"

        });

    }
);




// ==================================================
// REGISTER
// ==================================================

app.post(
    "/api/register",
    async function (
        req,
        res
    ) {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();

            const email =
                String(
                    req.body.email || ""
                )
                .trim()
                .toLowerCase();

            const password =
                String(
                    req.body.password || ""
                );
// ------------------------------------------
// INPUT LENGTH VALIDATION
// ------------------------------------------

if (
    username.length > 30 ||
    email.length > 100 ||
    password.length > 100
) {

    return res.status(400).json({

        success: false,

        message:
            "Input too long."

    });

}

            if (
                !username ||
                !email ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "All fields are required"

                });

            }


            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Password must be at least 8 characters"

                });

            }


            const existingUser =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email
                    FROM users
                    WHERE
                        username = ?
                        OR email = ?
                `).get(
                    username,
                    email
                );


            if (existingUser) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username or email already exists"

                });

            }


            const hashedPassword =
                await bcrypt.hash(
                    password,
                    12
                );


            const result =
                db.prepare(`
                    INSERT INTO users
                    (
                        username,
                        email,
                        password,
                        coins
                    )
                    VALUES (?, ?, ?, 0)
                `).run(
                    username,
                    email,
                    hashedPassword
                );


            return res.status(201).json({

                success: true,

                message:
                    "Account created successfully",

                userId:
                    result.lastInsertRowid

            });

        }

        catch (error) {

            console.error(
                "REGISTER ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// CUSTOMER LOGIN
// ==================================================
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        success: false,
        message: "Too many login attempts. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});
app.post(
    "/api/login",
    loginLimiter,
    async function (
        req,
        res
    ) {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                .trim()
                .toLowerCase();

            const password =
                String(
                    req.body.password || ""
                );


            if (
                !email ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Email and password are required"

                });

            }


            const user =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email,
                        password,
                        coins
                    FROM users
                    WHERE email = ?
                `).get(email);


            if (!user) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid email or password"

                });

            }


            const passwordMatch =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (!passwordMatch) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid email or password"

                });

            }


            const token =
                createUserSession(
                    user.id
                );


            res.setHeader(
                "Set-Cookie",
                "ff_user_session=" +
token +
"; HttpOnly; Path=/; SameSite=Strict; Max-Age=604800" +
(isProduction ? "; Secure" : "")
            );


            return res.json({

                success: true,

                message:
                    "Login successful",

                user: {

                    id:
                        user.id,

                    username:
                        user.username,

                    email:
                        user.email,

                    coins:
                        user.coins

                }

            });

        }

        catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// CUSTOMER SESSION STATUS
// ==================================================

app.get(
    "/api/me",
    function (
        req,
        res
    ) {

        try {

            const userId =
                getLoggedInUserId(req);


            if (!userId) {

                return res.json({

                    success: true,

                    authenticated: false,

                    user: null

                });

            }


            const user =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email,
                        coins
                    FROM users
                    WHERE id = ?
                `).get(
                    userId
                );


            if (!user) {

                return res.json({

                    success: true,

                    authenticated: false,

                    user: null

                });

            }


            return res.json({

                success: true,

                authenticated: true,

                user:
                    user

            });

        }

        catch (error) {

            console.error(
                "ME ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// CUSTOMER LOGOUT
// ==================================================

app.post(
    "/api/logout",
    function (
        req,
        res
    ) {

        const token =
            getUserSessionToken(req);


        if (token) {

            userSessions.delete(
                token
            );

        }


        res.setHeader(
            "Set-Cookie",
            "ff_user_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0" +
            (isProduction ? "; Secure" : "")
        );


        return res.json({

            success: true,

            message:
                "Logged out successfully"

        });

    }
);


// ==================================================
// DIRECT BUY COINS DISABLED
// ==================================================

app.post(
    "/api/buy-coins",
    function (
        req,
        res
    ) {

        return res.status(403).json({

            success: false,

            message:
                "Direct coin purchase disabled. Please submit payment proof for admin verification."

        });

    }
);

// ==================================================
// CUSTOMER - SUBMIT PAYMENT PROOF
// ==================================================

app.post(
    "/api/payment-proof",

    requireUser,

    upload.single("proof"),

    async function (
        req,
        res
    ) {

        try {

            const coins =
                Number(
                    req.body.coins
                );


            // ------------------------------------------
            // CHECK PAYMENT SCREENSHOT
            // ------------------------------------------

            if (!req.file) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Payment screenshot required"

                });

            }


            // ------------------------------------------
            // VALIDATE REAL FILE TYPE
            // ------------------------------------------

            const detectedType =
                await FileType.fromFile(
                    req.file.path
                );


            if (
                !detectedType ||
                ![
                    "jpg",
                    "jpeg",
                    "png",
                    "webp"
                ].includes(
                    detectedType.ext
                )
            ) {

                try {

                    fs.unlinkSync(
                        req.file.path
                    );

                }

                catch (deleteError) {

                    console.error(
                        "INVALID FILE CLEANUP ERROR:",
                        deleteError
                    );

                }

                return res.status(400).json({

                    success: false,

                    message:
                        "Valid JPG, PNG ya WEBP image required"

                });

            }


            // ------------------------------------------
            // VALIDATE COIN PACKAGE
            // ------------------------------------------

            if (
                !Number.isInteger(coins) ||
                ![10, 20, 30].includes(coins)
            ) {

                try {

                    fs.unlinkSync(
                        req.file.path
                    );

                }

                catch (deleteError) {

                    console.error(
                        "FILE CLEANUP ERROR:",
                        deleteError
                    );

                }

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid coin package"

                });

            }


            // ------------------------------------------
            // SAVE PAYMENT PROOF
            // ------------------------------------------

            db.prepare(`
                INSERT INTO payment_proofs
                (
                    user_id,
                    coins,
                    file_name,
                    original_name,
                    status
                )
                VALUES (?, ?, ?, ?, 'pending')
            `).run(
                req.userId,
                coins,
                req.file.filename,
                req.file.originalname
            );


            return res.json({

                success: true,

                message:
                    "Payment proof submitted successfully. Admin verification pending."

            });

        }

        catch (error) {

            console.error(
                "PAYMENT PROOF ERROR:",
                error
            );


            // Delete uploaded file if something fails
            if (
                req.file &&
                req.file.path
            ) {

                try {

                    fs.unlinkSync(
                        req.file.path
                    );

                }

                catch (deleteError) {

                    console.error(
                        "PAYMENT FILE CLEANUP ERROR:",
                        deleteError
                    );

                }

            }


            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);

// ==================================================
// GET ROOMS
// ==================================================

app.get(
    "/api/rooms",
    function (
        req,
        res
    ) {

        try {

            const rooms =
                db.prepare(`
                    SELECT
                        id,
                        name,
                        price
                    FROM rooms
                    ORDER BY id ASC
                `).all();


            return res.json({

                success: true,

                rooms:
                    rooms

            });

        }

        catch (error) {

            console.error(
                "GET ROOMS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ROOM DETAILS
// ==================================================

app.get(
    "/api/room-details/:roomId",

    requireUser,

    function (
        req,
        res
    ) {

        try {

            const roomId =
                Number(
                    req.params.roomId
                );


            if (!roomId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid room ID"

                });

            }


            const purchased =
                db.prepare(`
                    SELECT
                        id
                    FROM room_purchases
                    WHERE
                        user_id = ?
                        AND room_id = ?
                    LIMIT 1
                `).get(
                    req.userId,
                    roomId
                );


            if (!purchased) {

                return res.status(403).json({

                    success: false,

                    message:
                        "Room purchase required to view room details"

                });

            }


            const room =
                db.prepare(`
                    SELECT
                        id,
                        name,
                        price
                    FROM rooms
                    WHERE id = ?
                `).get(
                    roomId
                );


            if (!room) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Room not found"

                });

            }


            return res.json({

                success: true,

                room:
                    room,

                roomId:
                    "FF-" +
                    room.id +
                    "001",

                password:
                    "FF" +
                    room.id +
                    "2026",

                timing:
                    "8:00 PM"

            });

        }

        catch (error) {

            console.error(
                "ROOM DETAILS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// PURCHASE ROOM
// ==================================================

app.post(
    "/api/purchase-room",

    requireUser,

    function (
        req,
        res
    ) {

        try {

            const userId =
                req.userId;


            const roomId =
                Number(
                    req.body.roomId
                );


            if (!roomId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Room ID is required"

                });

            }


            const room =
                db.prepare(`
                    SELECT
                        id,
                        name,
                        price
                    FROM rooms
                    WHERE id = ?
                `).get(
                    roomId
                );


            if (!room) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Room not found"

                });

            }


            const purchaseRoom =
                db.transaction(
                    function () {

                        const user =
                            db.prepare(`
                                SELECT
                                    id,
                                    username,
                                    coins
                                FROM users
                                WHERE id = ?
                            `).get(
                                userId
                            );


                        if (!user) {

                            throw new Error(
                                "USER_NOT_FOUND"
                            );

                        }


                        if (
                            user.coins <
                            room.price
                        ) {

                            throw new Error(
                                "NOT_ENOUGH_COINS"
                            );

                        }


                        db.prepare(`
                            UPDATE users
                            SET coins =
                                coins - ?
                            WHERE id = ?
                        `).run(
                            room.price,
                            userId
                        );


                        db.prepare(`
                            INSERT INTO room_purchases
                            (
                                user_id,
                                room_id
                            )
                            VALUES (?, ?)
                        `).run(
                            userId,
                            roomId
                        );

                    }
                );


            try {

                purchaseRoom();

            }

            catch (transactionError) {

                if (
                    transactionError.message ===
                    "USER_NOT_FOUND"
                ) {

                    return res.status(404).json({

                        success: false,

                        message:
                            "User not found"

                    });

                }


                if (
                    transactionError.message ===
                    "NOT_ENOUGH_COINS"
                ) {

                    return res.status(400).json({

                        success: false,

                        message:
                            "Not enough coins"

                    });

                }


                throw transactionError;

            }


            const updatedUser =
                db.prepare(`
                    SELECT
                        coins
                    FROM users
                    WHERE id = ?
                `).get(
                    userId
                );


            return res.json({

                success: true,

                message:
                    room.name +
                    " purchased successfully",

                coins:
                    updatedUser.coins

            });

        }

        catch (error) {

            console.error(
                "PURCHASE ROOM ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// MY PURCHASED ROOMS
// ==================================================

app.get(
    "/api/my-rooms/:userId",

    requireUser,

    function (
        req,
        res
    ) {

        try {

            const userId =
                req.userId;


            const rooms =
                db.prepare(`
                    SELECT
                        room_purchases.id,
                        rooms.id AS room_id,
                        rooms.name,
                        rooms.price,
                        room_purchases.purchased_at
                    FROM room_purchases
                    JOIN rooms
                        ON room_purchases.room_id =
                           rooms.id
                    WHERE
                        room_purchases.user_id = ?
                    ORDER BY
                        room_purchases.id DESC
                `).all(
                    userId
                );


            return res.json({

                success: true,

                rooms:
                    rooms

            });

        }

        catch (error) {

            console.error(
                "MY ROOMS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// CUSTOMER - SUBMIT WITHDRAWAL
// ==================================================

app.post(
    "/api/withdrawal",

    requireUser,

    function (
        req,
        res
    ) {

        try {

            const userId =
                req.userId;


            const coins =
                Number(
                    req.body.coins
                );


            const method =
                String(
                    req.body.method || ""
                ).trim();


            const accountNumber =
                String(
                    req.body.account || ""
                ).trim();


            // ------------------------------------------
            // VALIDATE COINS
            // ------------------------------------------

            if (
                !Number.isInteger(coins) ||
                coins < 1
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Valid coins amount enter karein."

                });

            }


            // ------------------------------------------
            // VALIDATE METHOD
            // ------------------------------------------

            if (
                ![
                    "JazzCash",
                    "Easypaisa"
                ].includes(method)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid withdrawal method."

                });

            }


            // ------------------------------------------
// VALIDATE ACCOUNT NUMBER
// ------------------------------------------

if (!accountNumber) {

    return res.status(400).json({

        success: false,

        message:
            "Account number enter karein."

    });

}


// Pakistan mobile number validation
const normalizedAccount =
    accountNumber.replace(
        /[\s-]/g,
        ""
    );


const validAccount =
    /^(03\d{9}|\+923\d{9})$/.test(
        normalizedAccount
    );


if (!validAccount) {

    return res.status(400).json({

        success: false,

        message:
            "Valid JazzCash ya Easypaisa mobile number enter karein."

    });

}


            // ------------------------------------------
            // GET USER
            // ------------------------------------------

            const user =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email,
                        coins
                    FROM users
                    WHERE id = ?
                `).get(
                    userId
                );


            if (!user) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found."

                });

            }


            // ------------------------------------------
            // CHECK BALANCE
            // ------------------------------------------

            if (
                user.coins < coins
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Aapke wallet mein itne coins nahi hain."

                });

            }


            // ------------------------------------------
            // 1 COIN = RS 3
            // ------------------------------------------

            const amount =
                coins * 3;


            // ------------------------------------------
            // CREATE WITHDRAWAL
            // ------------------------------------------

            const createWithdrawal =
                db.transaction(
                    function () {

                        // Deduct coins
                        db.prepare(`
                            UPDATE users
                            SET coins =
                                coins - ?
                            WHERE id = ?
                        `).run(
                            coins,
                            userId
                        );


                        // Save withdrawal request
                        db.prepare(`
                            INSERT INTO withdrawal_requests
                            (
                                user_id,
                                coins,
                                amount,
                                method,
                                account_name,
                                account_number,
                                status
                            )
                            VALUES (?, ?, ?, ?, ?, ?, 'pending')
                        `).run(
                            userId,
                            coins,
                            amount,
                            method,
                            user.username,
                            accountNumber
                        );

                    }
                );


            createWithdrawal();


            // ------------------------------------------
            // UPDATED USER BALANCE
            // ------------------------------------------

            const updatedUser =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email,
                        coins
                    FROM users
                    WHERE id = ?
                `).get(
                    userId
                );


            // ------------------------------------------
            // SUCCESS RESPONSE
            // ------------------------------------------

            return res.json({

                success: true,

                message:
                    "Withdrawal request successfully submit ho gayi. Admin verification pending.",

                user:
                    updatedUser

            });

        }

        catch (error) {

            console.error(
                "WITHDRAWAL ERROR:",
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// CUSTOMER - MY WITHDRAWALS
// ==================================================

app.get(
    "/api/my-withdrawals",

    requireUser,

    function (
        req,
        res
    ) {

        try {

            const withdrawals =
                db.prepare(`
                    SELECT
                        id,
                        coins,
                        amount,
                        method,
                        account_name,
                        account_number,
                        status,
                        requested_at,
                        processed_at
                    FROM withdrawal_requests
                    WHERE user_id = ?
                    ORDER BY id DESC
                `).all(
                    req.userId
                );


            return res.json({

                success: true,

                withdrawals:
                    withdrawals

            });

        }

        catch (error) {

            console.error(
                "MY WITHDRAWALS ERROR:",
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);




// ==================================================
// ADMIN AUTHENTICATION
// ==================================================

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME;

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD;


if (
    !ADMIN_USERNAME ||
    !ADMIN_PASSWORD
) {

    console.error(
        "ADMIN_USERNAME aur ADMIN_PASSWORD .env file mein set nahi hain."
    );

    process.exit(1);

}


// ==================================================
// ADMIN LOGIN
// ==================================================
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        message: "Too many admin login attempts. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});
app.post(
    "/api/admin-login",
    adminLoginLimiter,
    function (
        req,
        res
    ) {

        try {

            const username =
                String(
                    req.body.username || ""
                ).trim();


            const password =
                String(
                    req.body.password || ""
                );


            if (
                !username ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username and password are required"

                });

            }


            if (
                username !==
                    ADMIN_USERNAME ||
                password !==
                    ADMIN_PASSWORD
            ) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid admin username or password"

                });

            }


            const token =
                createAdminSession();


            res.setHeader(
                "Set-Cookie",
                "ff_admin_session=" +
token +
"; HttpOnly; Path=/; SameSite=Strict; Max-Age=28800" +
(isProduction ? "; Secure" : "")
            );


            return res.json({

                success: true,

                message:
                    "Admin login successful",

                admin: true

            });

        }

        catch (error) {

            console.error(
                "ADMIN LOGIN ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN SESSION STATUS
// ==================================================

app.get(
    "/api/admin/status",
    requireAdmin,
    function (
        req,
        res
    ) {

        return res.json({

            success: true,

            admin: true

        });

    }
);


// ==================================================
// ADMIN LOGOUT
// ==================================================

app.post(
    "/api/admin-logout",
    function (
        req,
        res
    ) {

        const token =
            getAdminSessionToken(req);


        if (token) {

            adminSessions.delete(
                token
            );

        }


        res.setHeader(
            "Set-Cookie",
            "ff_admin_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0"
        );


        return res.json({

            success: true,

            message:
                "Admin logged out successfully"

        });

    }
);


// ==================================================
// ADMIN - GET USERS
// ==================================================

app.get(
    "/api/admin/users",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const users =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email,
                        coins,
                        created_at
                    FROM users
                    ORDER BY id DESC
                `).all();


            return res.json({

                success: true,

                users:
                    users

            });

        }

        catch (error) {

            console.error(
                "ADMIN USERS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - ADD COINS
// ==================================================

app.post(
    "/api/admin/add-coins",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const userId =
                Number(
                    req.body.userId
                );


            const coins =
                Number(
                    req.body.coins
                );


            if (
                !userId ||
                !coins
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "User ID and coins are required"

                });

            }


            if (
                !Number.isInteger(coins) ||
                coins < 1
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid coin amount"

                });

            }


            const user =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        coins
                    FROM users
                    WHERE id = ?
                `).get(
                    userId
                );


            if (!user) {

                return res.status(404).json({

                    success: false,

                    message:
                        "User not found"

                });

            }


            db.prepare(`
                UPDATE users
                SET coins =
                    coins + ?
                WHERE id = ?
            `).run(
                coins,
                userId
            );


            const updatedUser =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        coins
                    FROM users
                    WHERE id = ?
                `).get(
                    userId
                );


            return res.json({

                success: true,

                message:
                    "Coins added successfully",

                user:
                    updatedUser

            });

        }

        catch (error) {

            console.error(
                "ADMIN ADD COINS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - DASHBOARD STATS
// ==================================================

app.get(
    "/api/admin/stats",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const totalUsers =
                db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM users
                `).get().count;


            const totalCoins =
                db.prepare(`
                    SELECT
                        COALESCE(
                            SUM(coins),
                            0
                        ) AS total
                    FROM users
                `).get().total;


            const totalRooms =
                db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM rooms
                `).get().count;


            const coinPurchases =
                db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM coin_purchases
                `).get().count;


            const roomPurchases =
                db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM room_purchases
                `).get().count;


            const pendingPayments =
                db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM payment_proofs
                    WHERE status = 'pending'
                `).get().count;


            const pendingWithdrawals =
                db.prepare(`
                    SELECT COUNT(*) AS count
                    FROM withdrawal_requests
                    WHERE status = 'pending'
                `).get().count;


            return res.json({

                success: true,

                totalUsers:
                    totalUsers,

                totalCoins:
                    totalCoins,

                totalRooms:
                    totalRooms,

                coinPurchases:
                    coinPurchases,

                roomPurchases:
                    roomPurchases,

                pendingPayments:
                    pendingPayments,

                pendingWithdrawals:
                    pendingWithdrawals

            });

        }

        catch (error) {

            console.error(
                "ADMIN STATS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - COIN PURCHASE HISTORY
// ==================================================

app.get(
    "/api/admin/coin-purchases",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const purchases =
                db.prepare(`
                    SELECT
                        coin_purchases.id,
                        coin_purchases.user_id,
                        users.username,
                        users.email,
                        coin_purchases.coins,
                        coin_purchases.purchased_at
                    FROM coin_purchases
                    JOIN users
                        ON coin_purchases.user_id =
                           users.id
                    ORDER BY
                        coin_purchases.id DESC
                `).all();


            return res.json({

                success: true,

                purchases:
                    purchases

            });

        }

        catch (error) {

            console.error(
                "COIN PURCHASE HISTORY ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - ROOM PURCHASE HISTORY
// ==================================================

app.get(
    "/api/admin/room-purchases",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const purchases =
                db.prepare(`
                    SELECT
                        room_purchases.id,
                        room_purchases.user_id,
                        users.username,
                        users.email,
                        rooms.name AS room_name,
                        rooms.price,
                        room_purchases.purchased_at
                    FROM room_purchases
                    JOIN users
                        ON room_purchases.user_id =
                           users.id
                    JOIN rooms
                        ON room_purchases.room_id =
                           rooms.id
                    ORDER BY
                        room_purchases.id DESC
                `).all();


            return res.json({

                success: true,

                purchases:
                    purchases

            });

        }

        catch (error) {

            console.error(
                "ROOM PURCHASE HISTORY ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - PAYMENT PROOFS
// ==================================================

app.get(
    "/api/admin/payment-proofs",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const proofs =
                db.prepare(`
                    SELECT
                        payment_proofs.id,
                        payment_proofs.user_id,
                        users.username,
                        users.email,
                        payment_proofs.coins,
                        payment_proofs.file_name,
                        payment_proofs.original_name,
                        payment_proofs.status,
                        payment_proofs.submitted_at,
                        payment_proofs.verified_at
                    FROM payment_proofs
                    JOIN users
                        ON payment_proofs.user_id =
                           users.id
                    ORDER BY
                        payment_proofs.id DESC
                `).all();


            return res.json({

                success: true,

                proofs:
                    proofs

            });

        }

        catch (error) {

            console.error(
                "GET PAYMENT PROOFS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - VIEW PAYMENT PROOF IMAGE
// ==================================================

app.get(
    "/api/admin/payment-proofs/:id/image",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const proofId =
                Number(
                    req.params.id
                );


            if (!proofId) {

                return res.status(400).send(
                    "Invalid payment proof ID"
                );

            }


            const proof =
                db.prepare(`
                    SELECT
                        file_name
                    FROM payment_proofs
                    WHERE id = ?
                `).get(
                    proofId
                );


            if (!proof) {

                return res.status(404).send(
                    "Payment proof not found"
                );

            }


            const filePath =
                path.join(
                    paymentProofFolder,
                    proof.file_name
                );


            if (
                !fs.existsSync(filePath)
            ) {

                return res.status(404).send(
                    "Payment proof image not found"
                );

            }


            return res.sendFile(
                filePath
            );

        }

        catch (error) {

            console.error(
                "VIEW PAYMENT PROOF ERROR:",
                error
            );

            return res.status(500).send(
                "Server error"
            );

        }

    }
);


// ==================================================
// ADMIN - APPROVE PAYMENT
// ==================================================

app.post(
    "/api/admin/payment-proofs/:id/approve",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const proofId =
                Number(
                    req.params.id
                );


            if (!proofId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid payment proof ID"

                });

            }


            const proof =
                db.prepare(`
                    SELECT
                        id,
                        user_id,
                        coins,
                        status
                    FROM payment_proofs
                    WHERE id = ?
                `).get(
                    proofId
                );


            if (!proof) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Payment proof not found"

                });

            }


            if (
                proof.status !==
                "pending"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "This payment has already been processed"

                });

            }


            const approvePayment =
                db.transaction(
                    function () {

                        const updateUser =
                            db.prepare(`
                                UPDATE users
                                SET coins =
                                    coins + ?
                                WHERE id = ?
                            `).run(
                                proof.coins,
                                proof.user_id
                            );


                        if (
                            updateUser.changes !==
                            1
                        ) {

                            throw new Error(
                                "User not found"
                            );

                        }


                        db.prepare(`
                            INSERT INTO coin_purchases
                            (
                                user_id,
                                coins
                            )
                            VALUES (?, ?)
                        `).run(
                            proof.user_id,
                            proof.coins
                        );


                        db.prepare(`
                            UPDATE payment_proofs
                            SET
                                status = 'approved',
                                verified_at =
                                    CURRENT_TIMESTAMP
                            WHERE id = ?
                        `).run(
                            proofId
                        );

                    }
                );


            approvePayment();
createAuditLog(
    "PAYMENT_APPROVED",
    "payment_proof",
    proof.id,
    proof.user_id,
    `${proof.coins} coins payment approved`
);

            return res.json({

                success: true,

                message:
                    proof.coins +
                    " coins approved and added to user account"

            });

        }

        catch (error) {

            console.error(
                "APPROVE PAYMENT ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - REJECT WITHDRAWAL
// ==================================================

app.post(
    "/api/admin/withdrawals/:id/reject",

    requireAdmin,

    function (
        req,
        res
    ) {

        try {

            const withdrawalId =
                Number(
                    req.params.id
                );


            if (!withdrawalId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid withdrawal ID"

                });

            }


            // ------------------------------------------
            // GET WITHDRAWAL
            // ------------------------------------------

            const withdrawal =
                db.prepare(`
                    SELECT
                        id,
                        user_id,
                        coins,
                        amount,
                        status
                    FROM withdrawal_requests
                    WHERE id = ?
                `).get(
                    withdrawalId
                );


            if (!withdrawal) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Withdrawal request not found"

                });

            }


            // ------------------------------------------
            // CHECK STATUS
            // ------------------------------------------

            if (
                withdrawal.status !==
                "pending"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "This withdrawal has already been processed"

                });

            }


            // ------------------------------------------
            // REJECT + RETURN COINS
            // ------------------------------------------

            const rejectWithdrawal =
                db.transaction(
                    function () {

                        // Return original coins
                        db.prepare(`
                            UPDATE users
                            SET coins =
                                coins + ?
                            WHERE id = ?
                        `).run(
                            withdrawal.coins,
                            withdrawal.user_id
                        );


                        // Mark withdrawal rejected
                        db.prepare(`
                            UPDATE withdrawal_requests
                            SET
                                status = 'rejected',
                                processed_at =
                                    CURRENT_TIMESTAMP
                            WHERE id = ?
                        `).run(
                            withdrawalId
                        );

                    }
                );


            rejectWithdrawal();


            return res.json({

                success: true,

                message:
                    "Withdrawal rejected and coins returned to user"

            });

        }

        catch (error) {

            console.error(
                "REJECT WITHDRAWAL ERROR:",
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - GET WITHDRAWALS
// ==================================================

app.get(
    "/api/admin/withdrawals",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const withdrawals =
                db.prepare(`
                    SELECT
                        withdrawal_requests.id,
                        withdrawal_requests.user_id,
                        users.username,
                        users.email,
                        withdrawal_requests.coins,
                        withdrawal_requests.amount,
                        withdrawal_requests.method,
                        withdrawal_requests.account_name,
                        withdrawal_requests.account_number,
                        withdrawal_requests.status,
                        withdrawal_requests.requested_at,
                        withdrawal_requests.processed_at
                    FROM withdrawal_requests
                    JOIN users
                        ON withdrawal_requests.user_id =
                           users.id
                    ORDER BY
                        withdrawal_requests.id DESC
                `).all();


            return res.json({

                success: true,

                withdrawals:
                    withdrawals

            });

        }

        catch (error) {

            console.error(
                "ADMIN WITHDRAWALS ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);


// ==================================================
// ADMIN - APPROVE WITHDRAWAL
// ==================================================

app.post(
    "/api/admin/withdrawals/:id/approve",
    requireAdmin,
    function (
        req,
        res
    ) {

        try {

            const withdrawalId =
                Number(
                    req.params.id
                );


            if (!withdrawalId) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid withdrawal ID"

                });

            }


            const withdrawal =
                db.prepare(`
                    SELECT
                        id,
                        status
                    FROM withdrawal_requests
                    WHERE id = ?
                `).get(
                    withdrawalId
                );


            if (!withdrawal) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Withdrawal request not found"

                });

            }


            if (
                withdrawal.status !==
                "pending"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "This withdrawal has already been processed"

                });

            }


            db.prepare(`
                UPDATE withdrawal_requests
                SET
                    status = 'approved',
                    processed_at =
                        CURRENT_TIMESTAMP
                WHERE id = ?
            `).run(
                withdrawalId
            );


            return res.json({

                success: true,

                message:
                    "Withdrawal approved successfully"

            });

        }

        catch (error) {

            console.error(
                "APPROVE WITHDRAWAL ERROR:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Server error"

            });

        }

    }
);



// ==================================================
// 404 API HANDLER
// ==================================================

app.use(
    "/api",
    function (
        req,
        res
    ) {

        return res.status(404).json({

            success: false,

            message:
                "API route not found",

            path:
                req.originalUrl

        });

    }
);


// ==================================================
// GENERAL ERROR HANDLER
// ==================================================

app.use(
    function (
        error,
        req,
        res,
        next
    ) {

        console.error(
            "GENERAL SERVER ERROR:",
            error
        );


        if (
            res.headersSent
        ) {

            return next(error);

        }


        return res.status(500).json({

            success: false,

            message:
                "Server error"

        });

    }
);


// ==================================================
// START SERVER
// ==================================================
createDatabaseBackup();
cleanupOldDatabaseBackups();
setInterval(() => {
    createDatabaseBackup();
    cleanupOldDatabaseBackups();
}, 6 * 60 * 60 * 1000);
app.listen(
    PORT,
    function () {

        console.log("");

        console.log(
            "================================="
        );

        console.log(
            "FF BATTLE ARENA SERVER"
        );

        console.log(
            "================================="
        );

        console.log(
            "Server running at:"
        );

        console.log(
            `http://localhost:${PORT}`
        );

        console.log(
            "================================="
        );

        console.log("");

    }
);