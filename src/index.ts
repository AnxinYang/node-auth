import { RequestHandler } from 'express';
import { Response, Request } from 'express-serve-static-core';
import jwt from 'jsonwebtoken'

export type jwtPayload = string | object | Buffer
export type AuthCallback = (err: string | undefined, jwtToken: string, userInfo: jwtPayload, res: Response, req: Request) => Promise<void>

export interface AuthConfig {
    secret: string
    compare: (userInfo: any) => Promise<jwtPayload | null | undefined>
    signOptions?: jwt.SignOptions
    verifyOptions?: jwt.VerifyOptions
    headerKey?: string
    callback?: AuthCallback
}

export interface Auth {
    sign: RequestHandler,
    verify: RequestHandler
}

const defaultCallback: AuthCallback = async (err, jwtToken, jwtPayload, res) => {
    if (err) {
        res.status(401).send(err);
    } else {
        res.status(200).send(jwtPayload)
    }
}

const defaultConfig = {
    callback: defaultCallback,
    headerKey: 'x-auth-token'
}

export function Auth(config: AuthConfig): Auth {
    const { compare, secret, callback, signOptions, verifyOptions, headerKey } = { ...defaultConfig, ...config };

    return {
        sign: async function (req, res, next) {
            try {

                const payload = compare(req.body);
                if (!payload) throw Error('Invalid credential.');

                const token = sign(
                    payload,
                    secret,
                    signOptions
                );

                res.cookie('jwt', token);

                await callback(undefined, token, payload, res, req);
                next && next()

            } catch (e) {

                await callback(e.message, '', '', res, req);
                next && next(e)

            }
        },

        verify: async function (req, res, next) {

            const token = req.header(headerKey);

            if (!token) {
                res.status(401).send('Invalid Token.');
                return;
            };

            try {
                const decode = jwt.verify(token, secret, verifyOptions);
                res.locals.decoded = decode;
                next()
            } catch (e) {
                res.status(500).send();
                return;
            }
        }
    }
}



function sign(payload: jwtPayload, secret: jwt.Secret, options?: jwt.SignOptions): string {
    return jwt.sign(payload, secret, options)
}