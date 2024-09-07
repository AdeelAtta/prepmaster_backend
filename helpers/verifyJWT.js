const jwt = require(`jsonwebtoken`)
const apiResponse = require(`./apiResponse`)

function verifyJWT(req, res, next) {
   const accessToken = req.headers['authorization']?.split(' ')[1];
   const refreshToken = req.cookies.refreshToken;
 
   if (!accessToken || !refreshToken) {
     return apiResponse.unauthorizedResponse(res,"Access denied")
   }
 
   try {
     const decoded = jwt.verify(accessToken, refreshToken);
     req.user = decoded;
       next();
   } catch (error) {
     if (error.name === 'TokenExpiredError') {
       // Handle expired access token
       return apiResponse.unauthorized(res, "Access token expired");
   } else if (error.name === 'JsonWebTokenError') {
       // Handle invalid token
       return apiResponse.unauthorizedResponse(res, "Invalid token");
   } else {
       // Handle other errors
       return apiResponse.ErrorResponse(res, "An error occurred while verifying the token");
   }
   }
   }
 

 module.exports = verifyJWT

