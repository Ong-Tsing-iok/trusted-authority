import express from "express";
import { Server } from "socket.io";
import { logger, logSocketInfo, logInvalidSchemaWarning } from "./src/Logger.js";
import { createServer } from "https";

import { TrustedAuthority } from "./src/TrustedAuthority.js";
import { AuthRequestSchema, AuthResRequestSchema } from "./src/Validation.js";
import { InternalServerErrorMsg, InvalidArgumentErrorMsg } from "./src/Utils.js";
import CryptoHandler from "./src/CryptoHandler.js";

const SERVER_PORT = process.env.SERVER_PORT || 3001;
const KEY_PATH = process.env.KEY_PATH || "data/tls.key";
const CERT_PATH = process.env.CERT_PATH || "data/tls.cert";

const app = express();
app.set(`trust proxy`, true);

const options = {
  key: readFileSync(ConfigManager.serverKeyPath),
  cert: readFileSync(ConfigManager.serverCertPath),
  maxHttpBufferSize: 1e8, // 100 MB, may need to increase
};

const server = createServer(options, app);

server.listen(SERVER_PORT, () => {
  logger.info(`Server is running on port ${SERVER_PORT}`);
});

const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

io.on("connection", (socket) => {
  socket.ip = socket.handshake.address;
  // May need to get address from header if server is behind a proxy
  // See https://socket.io/how-to/get-the-ip-address-of-the-client
  socket.use(([event], next) => {
    socket.event = event;
    next();
  });
  logSocketInfo(socket, "Client connected.");

  socket.on("disconnect", () => {
    logSocketInfo(socket, "Client disconnected.", { event: undefined });
  });

  socket.on("auth", async (request, cb) => {
    try {
      const actionStr = "Client asks to authenticate";
      logSocketInfo(socket, actionStr + ".", request);

      const result = AuthRequestSchema.safeParse(request);
      if (!result.success) {
        logInvalidSchemaWarning(
          socket,
          actionStr,
          result.error.issues,
          request
        );
        cb({ errorMsg: InvalidArgumentErrorMsg });
        return;
      }
      const { publicKey } = result.data;

      // Get userid from server with public key
      // if not exist return not registered error

      // Generate random message for authentication
      const { message, cipher, spk } = await CryptoHandler.verifyGen(publicKey);
      socket.randKey = message;
      socket.pk = publicKey;
      logSocketInfo(
        socket,
        "Asking client to respond with correct authentication key."
      );
      cb({ cipher, spk });
      // Wait for auth-res
    } catch (error) {
      logSocketError(socket, error, request);
      cb({ errorMsg: InternalServerErrorMsg });
    }
  });

  // Authentication response event 
  socket.on('auth-res', async (request, cb) => {
    try {
      const actionStr = 'Client responds to authentication'
      logSocketInfo(socket, actionStr + '.', request)

      const result = AuthResRequestSchema.safeParse(request) // TODO: add attribute array
      if (!result.success) {
        logInvalidSchemaWarning(socket, actionStr, result.error.issues, request)
        cb({ errorMsg: InvalidArgumentErrorMsg })
        return
      }
      const { decryptedValue } = result.data

      if (socket.randKey !== decryptedValue) {
        logSocketWarning(socket, actionStr + ' with incorrect authentication key.', {
          ...request,
          randKey: socket.randKey
        })
        if (socket.userId) addFailure(socket.userId)
        cb({ errorMsg: 'Incorrect authentication key.' })
        return
      }
      // Authentication passed
      logSocketInfo(socket, 'Authentication key correct. Client is authenticated.')

      // Check if user attribute have changed. If not, return null. If changed, calculate new key and return.


      cb({ newKey: { } }) // new key or null
    } catch (error) {
      logSocketError(socket, error)
      cb({ errorMsg: InternalServerErrorMsg })
    }
  })
});

const TA = new TrustedAuthority();
