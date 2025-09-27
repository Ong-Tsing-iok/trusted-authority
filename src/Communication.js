import { logger } from "./Logger.js";

const CLOUD_SERVER_URL = process.env.CLOUD_SERVER_URL || "localhost:3001";

export async function getUserId(publicKey) {
  try {
    const response = await fetch(
      `${CLOUD_SERVER_URL}/userId?pk=${encodeURIComponent(publicKey)}`
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
