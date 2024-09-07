const Users = require(`../models/users`)
const apiResponse = require(`../helpers/apiResponse`)
const bcrypt = require('bcrypt');
const jwt = require(`jsonwebtoken`)

const axios = require('axios');


async function findUserByEmail(email) {
  const sanitizedEmail = email.toLowerCase().trim();
  return await Users.findOne({email:sanitizedEmail});
}

async function findUserByToken(token) {
  return await Users.findOne({ 'refreshToken.token': token}).exec();
}

async function findByIdAndUpdate(userId,data){

  return await Users.findByIdAndUpdate(
    userId,
    data,
    { new: true, runValidators: true }
  ).select('-password -refreshToken -createdAt');

}

async function addNewUser(userData) {
  try {
    const newUser = new Users(userData);
    return await newUser.save();
  } catch (error) {
    console.error('Error adding new user:', error);
    throw error;
  }
}

const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET

async function generateAccessToken(user,token_secret){
  return jwt.sign({
    id:user._id,
    name:user.username,
    email:user.email,
    roles:user.roles,
    picture:user?.picture
  },token_secret,{expiresIn:'15m'})
}

async function verifyRefreshToken(token){

  return jwt.verify(token,REFRESH_TOKEN_SECRET);

}

async function generateRefreshToken(user){
  return jwt.sign({id:user._id,name:user.username,email:user.email,roles:user.roles},REFRESH_TOKEN_SECRET,{expiresIn:'7d'})
}


const signup = async(req, res) => {

    const {name,email,password,role} = req.body;

    try{
      //Check for email if already exist
      const user = await findUserByEmail(email);
      if(user) return apiResponse.successResponse(res,"Email Already Exist");

      //Salting password before saving
      const salt = await bcrypt.genSalt(10);
      const saltedPassword = await bcrypt.hash(password,salt);

      //Add user to database
      const newUser = await addNewUser({username:name,email,password:saltedPassword,roles:[`${role}`]});

      return apiResponse.successResponseWithData(res,"Account Created Successfully !",newUser)


    }catch(err){
      return apiResponse.ErrorResponse(res, `Something went wrong! ${err.message}`);
    }
    
}

const login = async(req, res) => {

  const {email,password} = req.body;

  const user = await findUserByEmail(email);
  if(!user) return apiResponse.successResponse(res,"Email or Password is not correct");
  let isPasswordCorrect = await bcrypt.compare(password, user.password)
  if(!isPasswordCorrect) return apiResponse.successResponse(res,"Email or Password is not correct");



  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)

   const refreshToken = await generateRefreshToken(user);

   res.cookie(`refreshToken`,refreshToken,{
    expires,
    httpOnly:true,
    sameSite:"strict",
    secure:true
   })

   const updatedUser = await findByIdAndUpdate(user._id,{
    refreshToken: { token: refreshToken, expiresAt: expires }
  })


   const accessToken = await generateAccessToken(user,refreshToken);


  return apiResponse.successResponseWithData(res,"Login Successul",{name:updatedUser.username,email:updatedUser.email,roles:updatedUser.roles,accessToken});

}


const refreshToken = async (req,res) => {

  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return apiResponse.unauthorizedResponse(res, "Refresh token not found");
  }

  try{
    const decode = await verifyRefreshToken(refreshToken);
    if(!decode) return apiResponse.ErrorResponse(res, `Invalid Token`);

      const accessToken = await generateAccessToken(decode,refreshToken);

  return apiResponse.successResponseWithData(res,"Refresh",{name:decode.name,email:decode.email,roles:decode.roles,picture:decode?.picture,accessToken});

  }catch(err){
    if (err.name === 'TokenExpiredError') {
      const foundUser = await findUserByToken(refreshToken);
      if(foundUser){
        await Users.updateOne(
          { _id: foundUser._id },
          { 
            $unset: { 
              'refreshToken.token': 1, 
              'refreshToken.expiresAt': 1 
            } 
          }
        );
      }
      
      return apiResponse.unauthorizedResponse(res, "Refresh token expired");
    }
    return apiResponse.ErrorResponse(res, `Something went wrong! ${err.message}`);
  }


}


const logout = async (req,res) => {

  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.sendStatus(204);
  }

  try{

    const foundUser = await findUserByToken(refreshToken);
    if(foundUser){
      await Users.updateOne(
        { _id: foundUser._id },
        { 
          $unset: { 
            'refreshToken.token': 1, 
            'refreshToken.expiresAt': 1 
          } 
        }
      );
    }
  
    res.clearCookie('refreshToken', { httpOnly: true, sameSite:"strict", secure: true });
    return apiResponse.successResponse(res, "Logged out successfully");
  }catch(err){
    return apiResponse.ErrorResponse(res, `Logout failed: ${err.message}`);

  }

}


const auth0Login = async (req, res) => {
  const { auth0Id, email, name, auth0Token } = req.body;

  try {
    // Verify the Auth0 token
    const verifyResponse = await axios.get(`https://dev-8fuccwoxftr03gm2.us.auth0.com/userinfo`, {
      headers: { Authorization: `Bearer ${auth0Token}` }
    });

    if (verifyResponse.data.sub !== auth0Id) {
      return apiResponse.unauthorizedResponse(res, "Invalid Auth0 token");
    }

    let user = await findUserByEmail(email);

    if (!user) {
      // Create a new user if they don't exist
      const password = await bcrypt.hash(Math.random().toString(36).slice(-8), 10);
      user = await addNewUser({ username: name, email, password, auth0Id,picture:verifyResponse.data.picture });
    } else if (!user.auth0Id) {
      // If user exists but doesn't have an auth0Id, update it
      user = await findByIdAndUpdate(user._id, { auth0Id });
    }

    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); //7 days
    const refreshToken = await generateRefreshToken(user);

    res.cookie(`refreshToken`, refreshToken, {
      expires,
      httpOnly: true,
      sameSite: "strict",
      secure: true
    });

    const updatedUser = await findByIdAndUpdate(user._id, {
      refreshToken: { token: refreshToken, expiresAt: expires }
    });

    const accessToken = await generateAccessToken(user, refreshToken);

    return apiResponse.successResponseWithData(res, "Auth0 Login Successful", {
      name: updatedUser.username,
      email: updatedUser.email,
      roles: updatedUser.roles,
      picture:updatedUser.picture,
      accessToken
    });

  } catch (error) {
    console.error('Auth0 login error:', error);
    return apiResponse.ErrorResponse(res, `Auth0 login failed: ${error.message}`);
  }
};

module.exports = {signup,login,refreshToken,logout,auth0Login}