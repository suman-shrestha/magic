const { Router } = require("express");
const { inject } = require("awilix-express");
const Status = require("http-status");
const { getUser, generateToken } = require("../../../../config/jwt");
const logApi = require('../../../lib/LogApi');

const AuthController = {
  get router() {
    const router = Router();

    router.use(inject("authSerializer"));
    router.post("/magic-login", inject("magicLogin"), this.magicLogin);
    return router;
  },

  async magicLogin(req, res, next) {
      const { magicLogin, authSerializer } = req;
      req.user = [];
      const customer = await getUser(req.body.email);
      req.user = customer;
      const authHeader = req.headers.authorization;
      const { SUCCESS, ERROR, NOT_FOUND, UNAUTHORIZED } = magicLogin.outputs;
      magicLogin
          .on(SUCCESS, (customer) => {
              const token = generateToken(customer);
              res.status(Status.OK)
                  .header({ 'token': token.access_token })
                  .header({ 'refresh_token': token.refresh_token })
                  .header({ 'expires_at': token.expires_at })
                  .json({ 'customer': authSerializer.serialize(customer) });
              logApi(req, customer, 'SUCCESS');
          })
          .on(NOT_FOUND, (error) => 
              res.status(Status.NOT_FOUND).json({
                  type: 'NotFoundError',
                  details: error.details,
              });
          })
          .on(UNAUTHORIZED, (error) => {
              res.status(Status.UNAUTHORIZED).json({
                  type: error.type,
                  details: error.details,
              });
          })
          .on(ERROR, next);

      magicLogin.execute(req.user, authHeader);
  },
};

module.exports = AuthController;

