# AX-Node-Auth
A `Express` module for handling user authorization and authentication.

## Install
``` 
npm install ax-node-auth
```

## How to use

#### Initialization
```typescript
import {Auth} from 'ax-node-auth';

export {sign, verify} = Auth({
    secret: 'some_secret_string',
    compare:async (body: any) =>{
        const {id} = body;
        const user = await getUserInfoById(id);
        return user;
    }
})
```
#### Setup Router

```typescript
import {sign, verify} from './your_auth_file';
import express from 'express';

const router = express.Router();
router.post('/login_path',sign);

```

#### Setup Verify Middleware
```typescript
import {sign, verify} from './your_auth_file';
import express from 'express';

const router = express.Router();
router.get('/some_api',verify,(req, res)=>{
    // Get decoded info from token;
    const decoded = res.locals.decoded;
    // Some handler
});

```

## Documentation

### Auth(config: AuthConfig): Auth

Return a `Auth` object that contains `sign` and `verify` request handler. 

`AuthConfig`:

- `secret: string`: Secret or privateKey for `jsonwebtoken`

- `compare: (userInfo: any) => Promise<jwtPayload | null | undefined>`: An async function for compare body when `sign` handleing incoming request. If a `jwtPayload` is returned, the `jwtPayload` will be used to generate a jwt token.

    - `jwtPayload`: Could be an object literal, buffer or string representing valid JSON. 

- `signOptions[optional]: jwt.SignOptions`: Options for jwt to genereate token. For more info: please refer to [**jsonwebtoken**](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback) document.
- `verifyOptions[optional]`: jwt.VerifyOptions: Options for jwt to verify token. For more info: please refer to [**jsonwebtoken**](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) document.

- `headerKey[optional]`: Tells `verify` function which field token is locate in `Header`. Default: `x-auth-token`.

- `callback: async (err, jwtToken, jwtPayload, res,req) =>void; [optional]`: Provide an async function if you want to handle response youseft. By default, it returns `401` if `compare` return `undefined` or `null`. It returns `200` with body: 
```
{
    "data": {}, // The jwtPayload compare function return.
    "jwt": "some token string" // jwt token string
}
```
also, it will set cookie with key `jwt`.

###  sign: (req: Request, res: Response, next: NextFunction) => Promise<any>:
The `request handler` for login request.

###  verify: (req: Request, res: Response, next: NextFunction) => Promise<any>:
The `request handler/middleware` for verify incoming requests. If token is verified, the decoded information from token will be set to `res.locals.decoded`. If token is invalid, it will return a response with `401` code.