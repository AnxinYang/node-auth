import { NextFunction, Request, Response } from 'express';
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
    sign: (req: Request, res: Response, next: NextFunction) => Promise<any>,
    verify: (req: Request, res: Response, next: NextFunction) => Promise<any>
}

const defaultCallback: AuthCallback = async (err, jwtToken, jwtPayload, res, req) => {
    if (err) {
        res.status(401).send(err);
    } else {
        res.status(200).send({
            data: jwtPayload,
            jwt: jwtToken
        })
    }
}

const defaultConfig = {
    callback: defaultCallback,
    headerKey: 'x-auth-token',
    tokenInBody: true
}

export function Auth(config: AuthConfig): Auth {
    const { compare, secret, callback, signOptions, verifyOptions, headerKey, tokenInBody } = { ...defaultConfig, ...config };

    return {
        sign: async function (req, res, next) {
            try {

                const payload = await compare(req.body);
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

            const token = req.get(headerKey);

            if (!token) {
                res.status(401).send('No Token.');
                return;
            };

            try {
                const decode = jwt.verify(token, secret, verifyOptions);
                res.locals.decoded = decode;
                next()
            } catch (e) {
                console.log(e)
                res.status(401).send('Invalid Token.');
                return;
            }
        }
    }
}



function sign(payload: jwtPayload, secret: jwt.Secret, options?: jwt.SignOptions): string {
    return jwt.sign(payload, secret, options)
}