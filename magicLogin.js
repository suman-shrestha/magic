const Operation = require('src/app/Operation');
const { Magic } = require('@magic-sdk/admin');
const config = require('config');
const mAdmin = new Magic(config.api.magic.key);

class MagicLogin extends Operation {
  constructor({ customersRepository }) {
    super();
    this.customersRepository = customersRepository;
  }

  async execute(customerData, authHeader) {
    const { SUCCESS, NOT_FOUND, UNAUTHORIZED } = this.outputs;
    try {
        if (customerData && customerData.length === 0) {
          let error = {message: 'UnauthorizedError'};
          throw error;
        }

        const magicToken = authHeader.substring(7);
        // const magicToken = mAdmin.utils.parseAuthorizationHeader(authHeader);
        await mAdmin.token.validate(magicToken);
        console.log('After validate');
        const customer = this.customersRepository.serializeCustomer(customerData);
      if (!customer) {
          let error = {message: 'UnauthorizedError'};
          throw error;
      }

      return this.emit(SUCCESS, customer);
    } catch (error) {
        if(error.message === 'UnauthorizedError') {
            return this.emit(UNAUTHORIZED, error);
        } else if(error.code === 'ERROR_DIDT_EXPIRED') {
            return this.emit(UNAUTHORIZED, {
                type: 'TokenExpired',
                details: 'Passwordless Login Token has been expired',
            });
        } else {
            return this.emit(NOT_FOUND, {
                type: error.message,
                details: error.details,
            });
        }
    }
  }
}

MagicLogin.setOutputs(['SUCCESS', 'ERROR', 'NOT_FOUND', 'UNAUTHORIZED']);

module.exports = MagicLogin;

