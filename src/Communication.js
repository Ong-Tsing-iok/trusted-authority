import { logger } from "./Logger.js";

const CLOUD_SERVER_URL = process.env.CLOUD_SERVER_URL || "localhost:3001";
// This is used because we only have self-signed certificates.
// Should be removed in real deployment environment
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

export async function getUserId(publicKey) {
  try {
    const response = await fetch(
      `https://${CLOUD_SERVER_URL}/userId?pk=${encodeURIComponent(publicKey)}`
    );
    if (!response.ok) {
      // logger.warn(``)
      return null
    }
    const data = await response.json()
    console.log(data)
    return data.userId
  } catch (error) {
    logger.error(error);
    return null;
  }
}
