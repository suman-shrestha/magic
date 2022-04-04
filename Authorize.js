import { injectable } from 'inversify'
import axios from 'axios'

import { IAuthorizeService } from 'core/services/authorize'
import { LoginUser, RegisterUserResult, RegisterMatrixUserResult } from 'core/domain/authorize'
import { SocialError } from 'core/domain/common'
import { setToLocalStorage } from 'src/helpers'
import { HttpStatus } from 'src/constants/httpStatus'

/**
 * Firbase authorize service
 *
 * @export
 * @class AuthorizeService
 * @implements {IAuthorizeService}
 */
@injectable()
export class AuthorizeService implements IAuthorizeService {

public magicLogin = (email: string, token: string) => {
        return new Promise<LoginUser>((resolve, reject) => {
            const data = { email: email, token: token }
            setToLocalStorage('magic-login-access-token', JSON.stringify(token))
            const config = {
                headers: ['Authorization' : JSON.parse(localStorage.getItem('magic-login-access-token')],
                withCredentials: true,
            }

            axios
                .post('https://pipeline.cashback.io/api/login/magic-login', data, config)
                .then((result) => {
                    if (!result.data.customer) {
                        reject(
                            new SocialError(
                                HttpStatus.BAD_REQUEST,
                                'Invalid Email'
                            )
                        )
                    } else if (result.data.customer.status === 0) {
                      reject(
                        new SocialError(
                          '404',
                          result.headers.token
                        )
                      )
                    } else {
                        setToLocalStorage('auth-token-detail', JSON.stringify(result.headers));
                        resolve(
                            new LoginUser(
                                result.data.customer.user_id,
                                true,
                                '0',
                                result.data.customer.name,
                                result.data.customer.email
                            )
                        )
                    }
                })
                .catch((error) => {
                    if (error.message.includes('401')) {
                        reject(
                            new SocialError(
                                '401',
                                'Please check your email again'
                            )
                        )
                    } else {
                        reject(new SocialError(error.code, error.message))
                    }
                })
        })
    }
}
