// HMACSHA256

// https://www.npmjs.com/package/crypto-js
import * as CryptoJS from 'crypto-js';
import btoa from 'btoa';

let base64UrlEncode = string => {
  return btoa(encodeURIComponent(string));
};
let HMACSHA256 = CryptoJS.HmacSHA1;

let header = {
  "alg": "HS256",
  "typ": "JWT"
};

let payload = {
  "sub": "1234567890",
  "iat": 1300819370,
  "exp": 1300819380,
  "name": "John Doe",
  "admin": true
};

let secret = 'loremipsum';

// https://jwt.io/introduction/
// HMACSHA256(
//   base64UrlEncode(header) + "." +
//   base64UrlEncode(payload),
//   secret)

let encodedString = base64UrlEncode(header) + "." +
    base64UrlEncode(payload);

let signature = base64UrlEncode(HMACSHA256(encodedString, secret).toString());

let token = encodedString + '.' + signature;

console.log(token);
// https://developer.atlassian.com/static/connect/docs/latest/concepts/understanding-jwt.html
// <base64url-encoded header>.<base64url-encoded claims>.<base64url-encoded signature>
