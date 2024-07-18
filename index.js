import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import env from "dotenv";
import bcrypt from "bcrypt";
import GoogleStrategy from "passport-google-oauth2";
import otpGenerator from "otp-generator";
import nodemailer from "nodemailer";
import axios from "axios";
import crypto from "crypto";

// Load environment variables
env.config();

const app = express();
const allowedOrigins = [
  "http://localhost:3000",
  "https://kharthikasarees.onrender.com",
  "https://kharthikasarees.com",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (allowedOrigins.includes(origin) || !origin) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: {
    rejectUnauthorized: false, // This is generally used for self-signed certificates
  },
});

db.connect((err) => {
  if (err) {
    console.error("Connection error", err.stack);
  } else {
    console.log("Connected to the database");
  }
});

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 3 * 60 * 60 * 1000 },
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.send("Website is Live");
});

/*passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:4000/google/callback",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          // User does not exist, redirect to signup page
          const redirectUrl = `http://localhost:3000/signup`;
          return cb(null, { redirectUrl });
        } else {
          // User exists, redirect to signin page
          return cb(null, { redirectToSignin: true });
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  if (user.redirectUrl) {
    return cb(null, user.redirectUrl);
  } else if (user.redirectToSignin) {
    return cb(null, "/signin");
  } else {
    return cb(null, user);
  }
});

// Route to authenticate with Google
app.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

// Callback route after successful Google authentication
app.get("/google/callback", (req, res, next) => {
  passport.authenticate("google", async (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      // Authentication failed, redirect to failure URL
      return res.redirect("http://localhost:3000");
    }

    const { redirectUrl, redirectToSignin } = user;

    if (redirectUrl) {
      // Redirect to the signup page with firstname and lastname as parameters
      return res.redirect("http://localhost:3000/signup");
    } else if (redirectToSignin) {
      // Redirect to the signin page
      return res.redirect("http://localhost:3000/login");
    } else {
      // Default success redirection
      return res.redirect("http://localhost:3000/");
    }
  })(req, res, next);
}); */

// Signup route
app.post("/signup", async (req, res) => {
  const { firstname, lastname, email, password } = req.body;

  try {
    // Check if the email already exists
    const checkEmailQuery = "SELECT * FROM users WHERE email = $1";
    const checkEmailResult = await db.query(checkEmailQuery, [email]);

    if (checkEmailResult.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Encrypt the password
    const hashedPassword = await bcrypt.hash(password, 3);

    const values = [firstname, lastname, email, hashedPassword];
    const sql =
      "INSERT INTO users (firstname, lastname, email, password) VALUES ($1, $2, $3, $4)";

    db.query(sql, values, (err, result) => {
      if (err) {
        console.error("Error executing SQL query:", err);
        return res
          .status(500)
          .json({ error: "An error occurred while saving data." });
      }
      console.log("Rows affected:", result.rowCount);
      console.log("Data inserted successfully:", result.rows);
      return res.status(200).json({ success: true });
    });
  } catch (err) {
    console.error("Error encrypting password:", err);
    return res
      .status(500)
      .json({ error: "An error occurred while encrypting password." });
  }
});

// Signin route
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  console.log("Received data:", req.body);

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    console.log(result.rows);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log(user);
      const hashedPassword = user.password;

      // Compare the encrypted password
      const match = await bcrypt.compare(password, hashedPassword);

      if (match) {
        res.json({ firstName: user.firstname });
        console.log("Successful Login");
      } else {
        res.send("Incorrect Password");
        console.log("Incorrect Password");
      }
    } else {
      res.send("User not found");
      console.log("User not found");
    }
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ error: "An error occurred while processing the request." });
  }
});

// Update password route
app.post("/updatepassword", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Encrypt the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.query(
      "UPDATE users SET password = $1 WHERE email = $2",
      [hashedPassword, email]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Error updating password:", err);
    return res
      .status(500)
      .json({ error: "An error occurred while updating password" });
  }
});

// OTP generation and sending route
const otpStore = {};

app.post("/generate-otp", async (req, res) => {
  const { email } = req.body;

  const otp = otpGenerator.generate(6, {
    digits: true,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });

  try {
    // Store the OTP in the temporary store
    otpStore[email] = otp;
    console.log("from generate-otp " + otpStore[email]);

    // Send OTP via email (replace with your email sending logic)
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.APP_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: "OTP Verification",
      text: `Your OTP for verification is: ${otp}`,
    });

    res.status(200).send("OTP sent successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error sending OTP");
  }
});

// OTP verification route
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  console.log("from verify side " + otpStore[email]);
  try {
    if (otpStore[email] && otpStore[email] === otp) {
      delete otpStore[email];
      res.status(200).send("OTP verified successfully");
    } else {
      res.status(400).send("Invalid OTP");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error verifying OTP");
  }
});

// Update address route
app.post("/update-address", async (req, res) => {
  const { email, address, phonenumber } = req.body;

  if (!email || !address || !phonenumber) {
    return res
      .status(400)
      .json({ error: "Email, address, and phonenumber are required" });
  }

  const { addressLine1, city, state, pincode } = address;

  try {
    const result = await db.query(
      `
            UPDATE users 
            SET address = $1, city = $2, state = $3, pincode = $4, phonenumber = $5
            WHERE email = $6`,
      [addressLine1, city, state, pincode, phonenumber, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    return res
      .status(200)
      .json({ success: true, message: "Address updated successfully" });
  } catch (err) {
    console.error("Error updating address:", err);
    return res
      .status(500)
      .json({ error: "An error occurred while updating address" });
  }
});

app.get("/api/user", async (req, res) => {
  const { email } = req.query;

  try {
    const result = await db.query(
      "SELECT firstname, lastname, email, address, city, state, pincode, phonenumber FROM users WHERE email = $1",
      [email]
    );
    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (err) {
    console.error("Error fetching user data:", err);
    res
      .status(500)
      .json({ error: "An error occurred while fetching user data" });
  }
});

app.get("/api/get-order-details", async (req, res) => {
  const { email } = req.query;
  const fetchQuery = `
    SELECT 
      order_id, 
      user_firstname, 
      user_lastname, 
      user_email, 
      user_address, 
      user_city, 
      user_state, 
      user_pincode, 
      user_phonenumber, 
      transaction_id, 
      items, 
      total, 
      order_date,
      status 
    FROM 
      orders 
    WHERE 
      user_email = $1`;

  try {
    const result = await db.query(fetchQuery, [email]);

    if (result.rows.length > 0) {
      res.status(200).json(result.rows);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (err) {
    console.error("Error fetching user data:", err);
    res.status(500).json({ error: "An error occurred while fetching user data" });
  }
});

//Online Payment Gateway
app.post("/pay", async function (req, res) {
  try {
    console.log(req.body);
    const { name, amount, number, MID, transactionId } = req.body;

    const data = {
      merchantId: process.env.MERCHANT_ID,
      merchantTransactionId: transactionId,
      merchantUserId: MID,
      name: name,
      amount: amount, // amount in paise
      redirectUrl: `https://kharthikasarees.com/order-successful?transactionId=${transactionId}`,
      redirectMode: "GET",
      mobileNumber: number,
      paymentInstrument: {
        type: "PAY_PAGE",
      },
    };

    const payload = JSON.stringify(data);
    const payloadMain = Buffer.from(payload).toString("base64");
    const keyIndex = 1;
    const string = payloadMain + "/pg/v1/pay" + process.env.SALT_KEY;
    const sha256 = crypto.createHash("sha256").update(string).digest("hex");
    const checksum = sha256 + "###" + keyIndex;

    console.log("CheckSum : " + checksum);
    console.log("payload : " + payload);
    console.log("payload main : " + payloadMain);

    const prod_URL = "https://api.phonepe.com/apis/hermes/pg/v1/pay";

    const options = {
      method: "post",
      url: prod_URL,
      headers: {
        accept: "application/json",
        "Content-Type": "application/json",
        "X-VERIFY": checksum,
      },
      data: {
        request: payloadMain,
      },
    };

    // Make the request to PhonePe API from your backend
    axios
      .request(options)
      .then(function (response) {
        // Send the redirect URL to the frontend
        console.log(response.data);
        res.json({
          redirectUrl: response.data.data.instrumentResponse.redirectInfo.url,
        });
      })
      .catch(function (error) {
        console.error(error);
        res.status(500).send({ message: error.message, success: false });
      });
  } catch (error) {
    res.status(500).send({ message: error.message, success: false });
  }
});

// Endpoint to validate payment status
app.get("/status/:txnId", async function (req, res) {
  try {
    const merchantTransactionId = req.params["txnId"];
    const merchantId = process.env.MERCHANT_ID;
    const keyIndex = 1; // use correct key index
    const string =
      `https://api.phonepe.com/apis/hermes/pg/v1/status/${merchantId}/${merchantTransactionId}` +
      process.env.SALT_KEY;
    const sha256 = crypto.createHash("sha256").update(string).digest("hex");
    const checksum = sha256 + "###" + keyIndex;

    const options = {
      method: "GET",
      url: `https://api.phonepe.com/apis/hermes/pg/v1/status/${merchantId}/${merchantTransactionId}`,
      headers: {
        accept: "application/json",
        "Content-Type": "application/json",
        "X-VERIFY": checksum,
        "X-MERCHANT-ID": merchantId,
      },
    };

    axios
      .request(options)
      .then(async (response) => {
        if (response.data.success === true) {
          console.log(response.data);
          return res
            .status(200)
            .send({ success: true, message: "Payment Success" });
        } else {
          return res
            .status(400)
            .send({ success: false, message: "Payment Failure" });
        }
      })
      .catch((err) => {
        console.error(err);
        res.status(500).send({ msg: err.message });
      });
  } catch (error) {
    res.status(500).send({ message: error.message, success: false });
  }
});

//OrderSuccess Endpoint
app.post("/order-successful", async (req, res) => {
  const { transactionId, cart, userEmail } = req.body;

  const itemsWithIds = cart.map((item) => ({
    name: item.name,
    price: parseFloat(item.price),
    productId: item.id, // Assuming id is the field name in your cart items
  }));

  console.log(itemsWithIds); // Log items with IDs for verification

  if (!transactionId || !itemsWithIds || !userEmail) {
    return res.status(400).send("Missing required fields");
  }

  try {
    // Fetch user details from the database
    const user = await getUserDetails(userEmail);

    if (!user) {
      return res.status(404).send("User not found");
    }

    // Create order details including IDs
    const orderDetails = createOrderDetails(transactionId, itemsWithIds, user);

    // Save order details to the database
    await saveOrder(orderDetails);

    // Send confirmation emails with IDs
    await sendOrderEmails(user, orderDetails);

    // Respond with success
    res.status(200).send("Order processed successfully");
  } catch (error) {
    console.error("Error processing order:", error);
    res.status(500).send("An error occurred while processing your order.");
  }
});

// Function to fetch user details from database
const getUserDetails = async (email) => {
  try {
    const query = `
      SELECT firstname, lastname, email, address, city, state, pincode, phonenumber 
      FROM users 
      WHERE email = $1
    `;
    const result = await db.query(query, [email]);

    if (result.rows.length > 0) {
      return result.rows[0];
    } else {
      throw new Error("User not found");
    }
  } catch (err) {
    console.error("Error fetching user data:", err);
    throw err;
  }
};

// Function to create order details object
const createOrderDetails = (transactionId, cart, user) => {
  const items = cart.map((item) => ({
    name: item.name,
    price: parseFloat(item.price),
    productId: item.productId, // Assuming cart items have productId
  }));
  const total = items.reduce((total, item) => total + item.price, 0);

  return {
    user: user,
    transactionId: transactionId,
    items: items,
    total: total,
  };
};

// Function to save order details into the database
const saveOrder = async (orderDetails) => {
  try {
    const query = `
      INSERT INTO orders (user_firstname, user_lastname, user_email, user_address, user_city, user_state, user_pincode, user_phonenumber, transaction_id, items, total)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (transaction_id) DO NOTHING;
    `;
    const values = [
      orderDetails.user.firstname,
      orderDetails.user.lastname,
      orderDetails.user.email,
      orderDetails.user.address,
      orderDetails.user.city,
      orderDetails.user.state,
      orderDetails.user.pincode,
      orderDetails.user.phonenumber,
      orderDetails.transactionId,
      JSON.stringify(orderDetails.items),
      orderDetails.total,
    ];

    await db.query(query, values);
    console.log("Order saved to database");
  } catch (error) {
    console.error("Error saving order to database:", error);
    throw error;
  }
};

// Function to send order confirmation emails
const sendOrderEmails = async (user, orderDetails) => {
  const items = orderDetails.items;
  const total = orderDetails.total;
  const transactionId = orderDetails.transactionId;

  console.log("Setting up Nodemailer transporter...");
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.APP_PASSWORD,
    },
  });

  const userMailOptions = {
    from: process.env.GMAIL_USER,
    to: user.email,
    subject: "Order Confirmation - Kharthika Sarees",
    text: `Hello ${
      user.firstname
    },\n\nYour order has been placed successfully. Your transaction ID is ${transactionId}.\n\nItems:\n${items
      .map((item) => `${item.name}: ₹${item.price}`)
      .join(
        "\n"
      )}\n\nTotal: ₹${total},\n\nYou can expect your order to be delivered within 8 days. Please wait for the order confirmation mail from us.`,
  };

  const adminMailOptions = {
    from: process.env.GMAIL_USER,
    to: "kharthikasarees@gmail.com",
    subject: "New Order Received - Kharthika Sarees",
    text: `A new order has been placed.\n\nUser: ${
      user.firstname
    }\n\nPhone no: ${
      user.phonenumber
    }\n\nTransaction ID: ${transactionId}\nProduct IDs: ${items
      .map((item) => item.productId)
      .join(", ")}\nTotal: ₹${total}\n\nItems:\n${items
      .map((item) => `${item.name}: ₹${item.price}`)
      .join("\n")}\n\nShipping Address:\n${user.address}, ${user.city}, ${
      user.state
    }, ${user.pincode}`,
  };

  try {
    console.log("Sending email to user...");
    await transporter.sendMail(userMailOptions);
    console.log("Email sent to user");
  } catch (error) {
    console.error("Error sending email to user:", error);
    throw error;
  }

  try {
    console.log("Sending email to admin...");
    await transporter.sendMail(adminMailOptions);
    console.log("Email sent to admin");
  } catch (error) {
    console.error("Error sending email to admin:", error);
    throw error;
  }
};

app.post("/newsletter", async (req, res) => {
  const { email } = req.body;
  try {
    const checkEmailQuery = "SELECT * FROM newsletter WHERE email = $1";
    const checkEmailResult = await db.query(checkEmailQuery, [email]);

    if (checkEmailResult.rows.length > 0) {
      return res
        .status(200)
        .json({ error: "User already registered to the newsletter." });
    }

    const insertQuery = "INSERT INTO newsletter (email) VALUES ($1)";
    await db.query(insertQuery, [email]);

    return res
      .status(200)
      .json({ success: "Successfully subscribed to the newsletter!" });
  } catch (error) {
    console.error("Error inserting data into newsletter table:", error);
    return res
      .status(500)
      .json({ message: "Failed to subscribe. Please try again." });
  }
});

// Listen on port 4000
const port = 4000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
