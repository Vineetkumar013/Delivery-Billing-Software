const jwt = require("jsonwebtoken");
const LoginModel = require("../models/user");
const authConfig = require("../configs/auth.configs");
const AdminModel = require("../models/admin");

const verifyToken = (req, res, next) => {
    const token =
        req.get("Authorization")?.split("Bearer ")[1] ||
        req.headers["x-access-token"];

    if (!token) {
        return res.status(403).send({
            message: "no token provided! Access prohibited",
        });
    }

    jwt.verify(token, authConfig.secret, async (err, decoded) => {
        if (err) {
            console.log(err);
            return res.status(401).send({
                message: "UnAuthorised !",
            });
        }
        const user = await LoginModel.findOne({ _id: decoded.id });

        if (!user) {
            return res.status(400).send({
                message: "The user that this token belongs to does not exist",
            });
        }
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    const token =
        req.headers["x-access-token"] ||
        req.get("Authorization")?.split("Bearer ")[1];

    if (!token) {
        return res.status(403).send({
            message: "no token provided! Access prohibited",
        });
    }

    jwt.verify(token, authConfig.secret, async (err, decoded) => {
        if (err) {
            return res.status(401).send({
                message: "UnAuthorised ! Admin role is required! ",
            });
        }

        const user = await AdminModel.findOne({ _id: decoded.id });

        if (!user) {
            return res.status(400).send({
                message: "The admin that this  token belongs to does not exist",
            });
        }
        req.user = user;

        next();
    });
};



const authMiddleware = (allowedRoles) => {
    return async (req, res, next) => {
        try {
            // Get the token from the request headers
            const token =
                req.get("Authorization")?.split("Bearer ")[1] ||
                req.headers["x-access-token"];

            if (!token) {
                return res.status(403).send({
                    message: "no token provided! Access prohibited",
                });
            }

            // Verify the token
            jwt.verify(token, authConfig.secret, async (err, decoded) => {
                if (err) {
                    return res.status(401).send({
                        message: "UnAuthorised ! Admin role is required! ",
                    });
                } else {
                    const userId = decoded.userId;// Get the user ID from the decoded token
                    const user = await LoginModel.findById(userId);// Find the user in the database
                    // Check if the user exists and has the required role
                    if (user && allowedRoles.includes(user.role)) {
                        req.user = user; // Attach the user object to the request for further use in route handlers
                        next(); // User has the required role, proceed to the next middleware/route handler
                    } else {
                        res.status(403).json({ message: "Unauthorized" }); // User does not have the required role, return an error response
                    }
                }
            })
        } catch (error) {
            res.status(401).json({ message: "Invalid token" });
        }
    };
};


module.exports = {
    verifyToken,
    isAdmin,
    authMiddleware,
};
