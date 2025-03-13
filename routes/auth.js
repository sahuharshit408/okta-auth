// Required packages
const express = require('express');
const router = express.Router();
const axios = require('axios');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Okta API configuration
const OKTA_DOMAIN = process.env.OKTA_DOMAIN; // e.g. "https://your-domain.okta.com"
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// Headers for Okta API requests
const oktaHeaders = {
  'Accept': 'application/json',
  'Content-Type': 'application/json',
  'Authorization': `SSWS ${OKTA_API_TOKEN}`
};

// User Signup API
router.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    
    // Validate required fields
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields' 
      });
    }
    
    // Create user profile for Okta
    const newUser = {
      profile: {
        firstName: firstName,
        lastName: lastName,
        email: email,
        login: email
      },
      credentials: {
        password: {
          value: password
        }
      }
    };
    
    // Send request to Okta to create user
    const response = await axios.post(
      `${OKTA_DOMAIN}/api/v1/users?activate=true`,
      newUser,
      { headers: oktaHeaders }
    );
    
    return res.status(201).json({
      success: true,
      message: 'User created successfully',
      userId: response.data.id
    });
  } catch (error) {
    console.error('Signup error:', error.response?.data || error.message);
    
    // Handle Okta specific errors
    if (error.response?.data?.errorCauses) {
      return res.status(400).json({
        success: false,
        message: error.response.data.errorSummary,
        errors: error.response.data.errorCauses
      });
    }
    
    return res.status(500).json({
      success: false,
      message: 'Error creating user account'
    });
  }
});

// User Login API
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate required fields
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }
    
    // Authenticate user with Okta
    const authData = {
      username,
      password,
      grant_type: 'password',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: 'openid profile email'
    };
    
    // Convert to URL encoded form data
    const formData = new URLSearchParams(authData).toString();
    
    const response = await axios.post(
      `${OKTA_DOMAIN}/oauth2/v1/token`,
      formData,
      {
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return res.status(200).json({
      success: true,
      message: 'Login successful',
      token: response.data.access_token,
      id_token: response.data.id_token,
      expires_in: response.data.expires_in
    });
  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    
    return res.status(401).json({
      success: false,
      message: 'Authentication failed'
    });
  }
});

// Get User Profile API
router.get('/profile', async (req, res) => {
  try {
    // Get authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false, 
        message: 'No token provided' 
      });
    }
    
    const token = authHeader.split(' ')[1];
    
    // Get user info from Okta
    const response = await axios.get(
      `${OKTA_DOMAIN}/oauth2/v1/userinfo`,
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );
    
    return res.status(200).json({
      success: true,
      profile: response.data
    });
  } catch (error) {
    console.error('Profile fetch error:', error.response?.data || error.message);
    
    return res.status(401).json({
      success: false,
      message: 'Failed to fetch user profile'
    });
  }
});

// Edit User Profile API
router.put('/profile', async (req, res) => {
  try {
    // Get authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false, 
        message: 'No token provided' 
      });
    }
    
    const token = authHeader.split(' ')[1];
    
    // Get user info from token to identify the user
    let userInfo;
    try {
      const userInfoResponse = await axios.get(
        `${OKTA_DOMAIN}/oauth2/v1/userinfo`,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );
      userInfo = userInfoResponse.data;
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
    
    // User ID from the token info
    const userId = userInfo.sub;
    
    // Build profile update from request body
    const profileUpdate = {
      profile: {}
    };
    
    // Map of allowed profile fields and their corresponding Okta profile fields
    const allowedFields = {
      firstName: 'firstName',
      lastName: 'lastName',
      middleName: 'middleName',
      honorificPrefix: 'honorificPrefix',
      honorificSuffix: 'honorificSuffix',
      email: 'email',
      title: 'title',
      displayName: 'displayName',
      nickName: 'nickName',
      profileUrl: 'profileUrl',
      secondEmail: 'secondEmail',
      mobilePhone: 'mobilePhone',
      primaryPhone: 'primaryPhone',
      streetAddress: 'streetAddress',
      city: 'city',
      state: 'state',
      zipCode: 'zipCode',
      countryCode: 'countryCode',
      postalAddress: 'postalAddress',
      preferredLanguage: 'preferredLanguage',
      locale: 'locale',
      timezone: 'timezone',
      userType: 'userType',
      employeeNumber: 'employeeNumber',
      costCenter: 'costCenter',
      organization: 'organization',
      division: 'division',
      department: 'department',
      managerId: 'managerId',
      manager: 'manager'
    };
    
    // Fill profile update with provided fields
    for (const [key, value] of Object.entries(req.body)) {
      if (allowedFields[key] && value !== undefined) {
        profileUpdate.profile[allowedFields[key]] = value;
      }
    }
    
    // If no fields to update, return error
    if (Object.keys(profileUpdate.profile).length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }
    
    // Handle special case for login/username (requires additional verification)
    if (req.body.login) {
      // Note: Changing login often requires additional verification steps
      // Check Okta documentation for specific requirements
      profileUpdate.profile.login = req.body.login;
    }
    
    // Update user profile in Okta
    await axios.post(
      `${OKTA_DOMAIN}/api/v1/users/${userId}`,
      profileUpdate,
      { headers: oktaHeaders }
    );
    
    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully'
    });
  } catch (error) {
    console.error('Profile update error:', error.response?.data || error.message);
    
    // Handle Okta specific errors
    if (error.response?.data?.errorCauses) {
      return res.status(400).json({
        success: false,
        message: error.response.data.errorSummary,
        errors: error.response.data.errorCauses
      });
    }
    
    return res.status(500).json({
      success: false,
      message: 'Failed to update profile'
    });
  }
});

// Password Reset Request
router.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }
    
    // Request password reset from Okta
    await axios.post(
      `${OKTA_DOMAIN}/api/v1/users/${email}/lifecycle/reset_password?sendEmail=true`,
      {},
      { headers: oktaHeaders }
    );
    
    return res.status(200).json({
      success: true,
      message: 'Password reset email sent'
    });
  } catch (error) {
    console.error('Password reset error:', error.response?.data || error.message);
    
    return res.status(400).json({
      success: false,
      message: 'Failed to send password reset email'
    });
  }
});

// Logout (Revoke Token)
router.post('/logout', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token is required' 
      });
    }
    
    // Revoke the token
    const revokeData = new URLSearchParams({
      token,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      token_type_hint: 'access_token'
    }).toString();
    
    await axios.post(
      `${OKTA_DOMAIN}/oauth2/v1/revoke`,
      revokeData,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error.response?.data || error.message);
    
    return res.status(500).json({
      success: false,
      message: 'Failed to logout'
    });
  }
});

module.exports = router;
